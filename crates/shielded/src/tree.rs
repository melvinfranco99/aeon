//! Aeon's note commitment tree, tracked as a lean "frontier" (the O(depth)
//! rightmost-path state needed to append new leaves and compute the
//! current root) rather than a full witness-capable tree.
//!
//! **Scope note:** a full node only ever needs to (a) grow the tree as new
//! shielded outputs are confirmed, and (b) know recent anchors (roots) to
//! validate incoming spends against — it never needs to *produce* a
//! spend's Merkle witness itself. Only the spending wallet needs that, and
//! it reconstructs its own copy of the full tree locally from the
//! `/shielded-actions` stream (see `docs/PRIVACY.md`), the same way it
//! locally trial-decrypts incoming notes. A `Frontier` is enough for what
//! the node needs, and is far simpler than a full sharded/witnessed tree.

use incrementalmerkletree::frontier::Frontier;
use incrementalmerkletree::{Marking, Position, Retention};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use serde::{Deserialize, Serialize};
use shardtree::store::memory::MemoryShardStore;
use shardtree::ShardTree;

/// Orchard's fixed note commitment tree depth (32); asserted against the
/// `orchard` crate's own constant so a version bump can't silently
/// desynchronize the two.
pub const MERKLE_DEPTH: u8 = 32;
const _: () = assert!(MERKLE_DEPTH as usize == orchard::NOTE_COMMITMENT_TREE_DEPTH);

/// Rebuilds the *entire* note commitment tree from an ordered list of every
/// commitment ever confirmed (see `docs/PRIVACY.md`: a wallet fetches these
/// from a node's `/shielded-actions` endpoint, in the same
/// block/transaction/action order the node itself applies them in), and
/// returns the resulting anchor plus a Merkle witness for the leaf at
/// `target_position` — what's needed to spend the note that leaf commits
/// to.
///
/// **Scope note:** this rebuilds the whole tree from scratch on every call
/// rather than maintaining incremental client-side state, trading proving
/// preparation time for implementation simplicity — reasonable at Aeon's
/// hobby scale (see `docs/PRIVACY.md`).
pub fn witness_for_position(
    commitments_in_order: &[[u8; 32]],
    target_position: u64,
) -> Result<([u8; 32], MerklePath), String> {
    if commitments_in_order.is_empty() {
        return Err("no commitments to build a tree from".to_string());
    }
    if target_position >= commitments_in_order.len() as u64 {
        return Err("target position is out of range".to_string());
    }

    let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, MERKLE_DEPTH, 16> =
        ShardTree::new(MemoryShardStore::empty(), 100);

    let last_index = commitments_in_order.len() - 1;
    for (i, cmx_bytes) in commitments_in_order.iter().enumerate() {
        let leaf = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(cmx_bytes))
            .ok_or_else(|| format!("invalid commitment bytes at position {i}"))?;
        // Every leaf is marked (witnessable), since we don't know up front
        // which position(s) the caller will ask to witness across
        // different calls; the final leaf also carries the checkpoint we
        // read the anchor/witness back out from.
        let retention = if i == last_index {
            Retention::Checkpoint {
                id: 0u32,
                marking: Marking::Marked,
            }
        } else {
            Retention::Marked
        };
        tree.append(leaf, retention).map_err(|e| format!("{e:?}"))?;
    }

    let root = tree
        .root_at_checkpoint_id(&0)
        .map_err(|e| format!("{e:?}"))?
        .ok_or_else(|| "tree has no checkpoint".to_string())?;
    let merkle_path = tree
        .witness_at_checkpoint_id(Position::from(target_position), &0)
        .map_err(|e| format!("{e:?}"))?
        .ok_or_else(|| "no witness available for that position".to_string())?;

    Ok((root.to_bytes(), merkle_path.into()))
}

/// The append-only note commitment tree's current frontier.
#[derive(Clone)]
pub struct CommitmentFrontier(Frontier<MerkleHashOrchard, MERKLE_DEPTH>);

#[derive(Serialize, Deserialize)]
struct FrontierParts {
    position: Option<u64>,
    leaf: Option<MerkleHashOrchard>,
    ommers: Vec<MerkleHashOrchard>,
}

impl CommitmentFrontier {
    pub fn empty() -> Self {
        CommitmentFrontier(Frontier::empty())
    }

    /// Appends a note commitment (in the canonical per-block, per-bundle,
    /// per-action order — see `aeon_storage::Store`) to the tree.
    pub fn append(&mut self, cmx_bytes: [u8; 32]) -> Result<(), String> {
        let leaf = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&cmx_bytes))
            .ok_or_else(|| "invalid note commitment bytes".to_string())?;
        self.0.append(leaf);
        Ok(())
    }

    /// The tree's current root — the anchor a new shielded spend proven
    /// against "now" would use.
    pub fn root_bytes(&self) -> [u8; 32] {
        self.0.root().to_bytes()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let parts = match self.0.value() {
            None => FrontierParts {
                position: None,
                leaf: None,
                ommers: vec![],
            },
            Some(nef) => {
                let (position, leaf, ommers) = nef.clone().into_parts();
                FrontierParts {
                    position: Some(u64::from(position)),
                    leaf: Some(leaf),
                    ommers,
                }
            }
        };
        bincode::serialize(&parts).expect("frontier serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let parts: FrontierParts = bincode::deserialize(bytes).map_err(|e| e.to_string())?;
        match (parts.position, parts.leaf) {
            (None, None) => Ok(CommitmentFrontier::empty()),
            (Some(pos), Some(leaf)) => {
                let frontier = Frontier::from_parts(Position::from(pos), leaf, parts.ommers)
                    .map_err(|e| format!("{e:?}"))?;
                Ok(CommitmentFrontier(frontier))
            }
            _ => Err("corrupt frontier encoding: position/leaf presence mismatch".to_string()),
        }
    }
}

impl Default for CommitmentFrontier {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_cmx(byte: u8) -> [u8; 32] {
        // Not every 32-byte string is a valid Pallas base field element, but
        // dividing by a prime-adjacent small constant keeps this comfortably
        // below the modulus for any test byte value.
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        bytes
    }

    #[test]
    fn empty_frontier_round_trips_through_bytes() {
        let frontier = CommitmentFrontier::empty();
        let bytes = frontier.to_bytes();
        let restored = CommitmentFrontier::from_bytes(&bytes).unwrap();
        assert_eq!(frontier.root_bytes(), restored.root_bytes());
    }

    #[test]
    fn appending_changes_the_root_and_survives_a_round_trip() {
        let mut frontier = CommitmentFrontier::empty();
        let empty_root = frontier.root_bytes();
        frontier.append(fake_cmx(7)).unwrap();
        let root_after_one = frontier.root_bytes();
        assert_ne!(empty_root, root_after_one);

        let bytes = frontier.to_bytes();
        let mut restored = CommitmentFrontier::from_bytes(&bytes).unwrap();
        assert_eq!(restored.root_bytes(), root_after_one);

        frontier.append(fake_cmx(9)).unwrap();
        restored.append(fake_cmx(9)).unwrap();
        assert_eq!(frontier.root_bytes(), restored.root_bytes());
    }

    #[test]
    fn witness_matches_a_frontier_built_from_the_same_commitments() {
        let commitments: Vec<[u8; 32]> = (1..=5u8).map(fake_cmx).collect();

        let mut frontier = CommitmentFrontier::empty();
        for cmx in &commitments {
            frontier.append(*cmx).unwrap();
        }

        let (anchor_bytes, merkle_path) = witness_for_position(&commitments, 2).unwrap();
        assert_eq!(
            anchor_bytes,
            frontier.root_bytes(),
            "witness_for_position's anchor should match a frontier built from the same leaves"
        );

        let leaf = Option::<orchard::note::ExtractedNoteCommitment>::from(
            orchard::note::ExtractedNoteCommitment::from_bytes(&commitments[2]),
        )
        .unwrap();
        let computed_root = merkle_path.root(leaf);
        assert_eq!(
            computed_root.to_bytes(),
            anchor_bytes,
            "the witness should authenticate leaf 2 up to the same anchor"
        );
    }

    #[test]
    fn witness_rejects_an_out_of_range_position() {
        let commitments: Vec<[u8; 32]> = (1..=3u8).map(fake_cmx).collect();
        assert!(witness_for_position(&commitments, 10).is_err());
    }
}
