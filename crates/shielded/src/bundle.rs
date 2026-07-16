//! Building, proving, verifying, and (de)serializing Aeon's shielded
//! bundles. Wraps `orchard::Bundle<Authorized, i64>` end to end using the
//! real `orchard` builder/circuit APIs (see `docs/PRIVACY.md`); the
//! `orchard` crate has no built-in wire serialization, so this module
//! implements one manually, component by component.

use std::sync::OnceLock;

use incrementalmerkletree::Hashable;
use nonempty::NonEmpty;
use orchard::builder::{Builder, BundleType};
use orchard::bundle::{Authorized, BundleVersion, Flags, TxVersion};
use orchard::circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey};
use orchard::keys::{
    FullViewingKey, IncomingViewingKey, PreparedIncomingViewingKey, SpendAuthorizingKey,
};
use orchard::note::{ExtractedNoteCommitment, Note, Nullifier, TransmittedNoteCiphertext};
use orchard::note_encryption::IronwoodDomain;
use orchard::primitives::redpallas::{self, Binding, SpendAuth};
use orchard::tree::MerklePath;
use orchard::value::{NoteValue, ValueCommitment};
use orchard::{Action, Address, Anchor, Bundle, Proof};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zcash_note_encryption::try_note_decryption;

/// Aeon pins a single, fixed Orchard bundle/circuit version for consensus:
/// the "Ironwood" value pool on the current, secure ("fixed", post-NU6.3)
/// circuit — never the historical `InsecurePreNu6_2` circuit, which had a
/// documented soundness bug in real Zcash deployments before it was
/// patched. Ironwood (rather than the plain post-NU6.3 Orchard pool) is
/// chosen specifically because it permits cross-address transfers: Zcash's
/// post-NU6.3 Orchard pool *forbids* paying an arbitrary shielded address
/// (a policy choice tied to Zcash's own transparent/shielded turnstile
/// economics), but Aeon's whole point is letting anyone pay any shielded
/// recipient. All Aeon nodes must agree on this exact `orchard` crate
/// version (pinned in `Cargo.toml`) for the shielded pool to reach
/// consensus at all.
pub fn bundle_version() -> BundleVersion {
    BundleVersion::ironwood_v3()
}
pub const CIRCUIT_VERSION: OrchardCircuitVersion = OrchardCircuitVersion::PostNu6_3;
pub const TX_VERSION: TxVersion = TxVersion::V6;

/// The zk-SNARK proving key. Expensive to build (real proving-key
/// generation, not just loading a file); built once per process.
pub fn proving_key() -> &'static ProvingKey {
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    PK.get_or_init(|| ProvingKey::build(CIRCUIT_VERSION))
}

/// The zk-SNARK verifying key. Every node must derive the *same* key, since
/// it's consensus-critical; it's deterministic given `CIRCUIT_VERSION` and
/// the `orchard`/`halo2` crate versions pinned in `Cargo.toml`.
pub fn verifying_key() -> &'static VerifyingKey {
    static VK: OnceLock<VerifyingKey> = OnceLock::new();
    VK.get_or_init(|| VerifyingKey::build(CIRCUIT_VERSION))
}

#[derive(Debug, Error)]
pub enum ShieldedBundleError {
    #[error("failed to build bundle: {0}")]
    Build(String),
    #[error("bundle builder produced no actions")]
    Empty,
    #[error("failed to compute bundle sighash: {0}")]
    Commitment(String),
    #[error("failed to create zk-SNARK proof: {0}")]
    Prove(String),
    #[error("failed to finalize bundle signatures: {0}")]
    Finalize(String),
    #[error("proof verification failed: {0}")]
    VerifyProof(String),
    #[error("spend authorization signature verification failed")]
    InvalidSpendAuthSignature,
    #[error("binding signature verification failed")]
    InvalidBindingSignature,
    #[error("bundle deserialization error: {0}")]
    Deserialize(String),
}

/// A fully-built, proved and signed Aeon shielded bundle, ready to be
/// embedded in a transaction.
#[derive(Clone)]
pub struct ShieldedBundle(pub Bundle<Authorized, i64>);

impl std::fmt::Debug for ShieldedBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShieldedBundle")
            .field("actions", &self.0.actions().len())
            .field("value_balance", self.0.value_balance())
            .finish()
    }
}

impl ShieldedBundle {
    pub fn inner(&self) -> &Bundle<Authorized, i64> {
        &self.0
    }

    /// Net value leaving the shielded pool (positive) or entering it
    /// (negative); see `docs/CONSENSUS.md` for the transparent/shielded
    /// balance equation this feeds into.
    pub fn value_balance(&self) -> i64 {
        *self.0.value_balance()
    }

    /// Verifies the bundle's zk-SNARK proof, every action's spend
    /// authorization signature, and the binding signature tying the
    /// bundle's hidden per-action values to its public `value_balance`.
    /// Does **not** check nullifier-reuse or anchor validity — those need
    /// chain state, and are the caller's (`aeon-core`/`aeon-storage`)
    /// responsibility.
    pub fn verify(&self) -> Result<(), ShieldedBundleError> {
        self.0
            .verify_proof(verifying_key())
            .map_err(|e| ShieldedBundleError::VerifyProof(format!("{e:?}")))?;

        let sighash: [u8; 32] = self
            .0
            .commitment(TX_VERSION)
            .map_err(|e| ShieldedBundleError::Commitment(format!("{e:?}")))?
            .into();

        for action in self.0.actions() {
            action
                .rk()
                .verify(&sighash, action.authorization())
                .map_err(|_| ShieldedBundleError::InvalidSpendAuthSignature)?;
        }

        let bvk = self.0.binding_validating_key();
        bvk.verify(&sighash, self.0.authorization().binding_signature())
            .map_err(|_| ShieldedBundleError::InvalidBindingSignature)?;

        Ok(())
    }

    /// Nullifiers of every note this bundle spends (empty for an
    /// output-only/shielding bundle).
    pub fn nullifiers(&self) -> Vec<Nullifier> {
        self.0.actions().iter().map(|a| *a.nullifier()).collect()
    }

    /// The same nullifiers as [`Self::nullifiers`], as raw bytes — the form
    /// `aeon-storage`'s nullifier set actually stores.
    pub fn nullifier_bytes(&self) -> Vec<[u8; 32]> {
        self.0
            .actions()
            .iter()
            .map(|a| a.nullifier().to_bytes())
            .collect()
    }

    /// Note commitments this bundle adds to the note commitment tree.
    pub fn note_commitments(&self) -> Vec<ExtractedNoteCommitment> {
        self.0.actions().iter().map(|a| *a.cmx()).collect()
    }

    /// The same commitments as [`Self::note_commitments`], as raw bytes.
    pub fn note_commitment_bytes(&self) -> Vec<[u8; 32]> {
        self.0
            .actions()
            .iter()
            .map(|a| a.cmx().to_bytes())
            .collect()
    }

    /// The anchor (Merkle root) this bundle's spends were proven against.
    pub fn anchor_bytes(&self) -> [u8; 32] {
        self.0.anchor().to_bytes()
    }

    /// A commitment to this bundle's entire contents (proof, signatures,
    /// value balance, anchor, every action), suitable for binding a
    /// mixed transparent+shielded [`crate::types::Transaction`]'s txid and
    /// transparent signatures to the shielded part too — see the doc
    /// comment on `Transaction` in `aeon-core`.
    pub fn tx_commitment_bytes(&self) -> Result<[u8; 32], ShieldedBundleError> {
        Ok(self
            .0
            .commitment(TX_VERSION)
            .map_err(|e| ShieldedBundleError::Commitment(format!("{e:?}")))?
            .into())
    }

    /// Attempts trial-decryption of every action's output against `ivk`,
    /// returning any notes addressed to it. This is how a wallet discovers
    /// incoming shielded payments — see `docs/PRIVACY.md`: the node never
    /// needs to see any viewing key, the wallet scans locally.
    pub fn scan_for_incoming_notes(
        &self,
        ivk: &IncomingViewingKey,
    ) -> Vec<(usize, Note, Address, [u8; 512])> {
        let prepared = PreparedIncomingViewingKey::new(ivk);
        self.0
            .actions()
            .iter()
            .enumerate()
            .filter_map(|(i, action)| {
                let domain = IronwoodDomain::for_action(action);
                try_note_decryption(&domain, &prepared, action)
                    .map(|(note, addr, memo)| (i, note, addr, memo))
            })
            .collect()
    }
}

/// Builds, proves and signs an output-only ("shielding") bundle: moves
/// `value_quarks` from Aeon's transparent pool into a single new shielded
/// note owned by `recipient`. Has no spends, so it needs no anchor/Merkle
/// path — an empty-tree anchor is used, matching `orchard`'s own
/// shielding-bundle pattern.
pub fn build_shielding_bundle(
    recipient: Address,
    value_quarks: u64,
) -> Result<ShieldedBundle, ShieldedBundleError> {
    let anchor = Anchor::from(orchard::tree::MerkleHashOrchard::empty_root(32.into()));
    let flags = Flags::SPENDS_DISABLED;

    let mut builder = Builder::new(BundleType::DEFAULT, bundle_version(), flags, anchor)
        .map_err(|e| ShieldedBundleError::Build(format!("{e:?}")))?;
    builder
        .add_output(
            None,
            recipient,
            NoteValue::from_raw(value_quarks),
            [0u8; 512],
        )
        .map_err(|e| ShieldedBundleError::Build(format!("{e:?}")))?;

    finish_bundle(builder, &[])
}

/// Builds, proves and signs a bundle spending a previously-received note and
/// paying one or more shielded recipients (a fully private send), or a
/// "deshielding" send if the value balance is left positive by paying out
/// less than the spent note's value with no shielded change output. The
/// caller supplies the note together with its Merkle witness (see
/// `aeon-storage`'s note commitment tree for where that comes from).
pub fn build_spend_bundle(
    spend_fvk: FullViewingKey,
    spend_sk_for_signing: &SpendAuthorizingKey,
    note: Note,
    merkle_path: MerklePath,
    anchor: Anchor,
    outputs: &[(Address, u64)],
) -> Result<ShieldedBundle, ShieldedBundleError> {
    let flags = bundle_version().default_flags();
    let mut builder = Builder::new(BundleType::DEFAULT, bundle_version(), flags, anchor)
        .map_err(|e| ShieldedBundleError::Build(format!("{e:?}")))?;
    builder
        .add_spend(spend_fvk, note, merkle_path)
        .map_err(|e| ShieldedBundleError::Build(format!("{e:?}")))?;
    for (recipient, value) in outputs {
        builder
            .add_output(None, *recipient, NoteValue::from_raw(*value), [0u8; 512])
            .map_err(|e| ShieldedBundleError::Build(format!("{e:?}")))?;
    }

    finish_bundle(builder, std::slice::from_ref(spend_sk_for_signing))
}

fn finish_bundle(
    builder: Builder,
    spend_auth_keys: &[SpendAuthorizingKey],
) -> Result<ShieldedBundle, ShieldedBundleError> {
    let mut rng = OsRng;
    let (unauthorized, _meta) = builder
        .build::<i64>(rng)
        .map_err(|e| ShieldedBundleError::Build(format!("{e:?}")))?
        .ok_or(ShieldedBundleError::Empty)?;

    let sighash: [u8; 32] = unauthorized
        .commitment(TX_VERSION)
        .map_err(|e| ShieldedBundleError::Commitment(format!("{e:?}")))?
        .into();

    let proven = unauthorized
        .create_proof(proving_key(), rng)
        .map_err(|e| ShieldedBundleError::Prove(format!("{e:?}")))?;

    rng = OsRng;
    let bundle = proven
        .apply_signatures(rng, sighash, spend_auth_keys)
        .map_err(|e| ShieldedBundleError::Finalize(format!("{e:?}")))?;

    Ok(ShieldedBundle(bundle))
}

// ---- manual (de)serialization -----------------------------------------

#[derive(Serialize, Deserialize)]
struct ActionBytes {
    nf: [u8; 32],
    rk: [u8; 32],
    cmx: [u8; 32],
    epk_bytes: [u8; 32],
    enc_ciphertext: Vec<u8>,
    out_ciphertext: Vec<u8>,
    cv_net: [u8; 32],
    spend_auth_sig: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct BundleBytes {
    actions: Vec<ActionBytes>,
    flags_byte: u8,
    value_balance: i64,
    anchor: [u8; 32],
    proof: Vec<u8>,
    binding_signature: Vec<u8>,
}

impl From<&ShieldedBundle> for BundleBytes {
    fn from(b: &ShieldedBundle) -> Self {
        let bundle = &b.0;
        let actions = bundle
            .actions()
            .iter()
            .map(|a| ActionBytes {
                nf: a.nullifier().to_bytes(),
                rk: <[u8; 32]>::from(a.rk().clone()),
                cmx: a.cmx().to_bytes(),
                epk_bytes: a.encrypted_note().epk_bytes,
                enc_ciphertext: a.encrypted_note().enc_ciphertext.to_vec(),
                out_ciphertext: a.encrypted_note().out_ciphertext.to_vec(),
                cv_net: a.cv_net().to_bytes(),
                spend_auth_sig: <[u8; 64]>::from(a.authorization()).to_vec(),
            })
            .collect();
        BundleBytes {
            actions,
            flags_byte: bundle.flag_byte(),
            value_balance: *bundle.value_balance(),
            anchor: bundle.anchor().to_bytes(),
            proof: bundle.authorization().proof().as_ref().to_vec(),
            binding_signature: <[u8; 64]>::from(bundle.authorization().binding_signature())
                .to_vec(),
        }
    }
}

impl TryFrom<BundleBytes> for ShieldedBundle {
    type Error = ShieldedBundleError;

    fn try_from(bb: BundleBytes) -> Result<Self, Self::Error> {
        let flags = Flags::from_byte(bb.flags_byte, bundle_version())
            .ok_or_else(|| ShieldedBundleError::Deserialize("invalid flags byte".into()))?;
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(bb.anchor))
            .ok_or_else(|| ShieldedBundleError::Deserialize("invalid anchor".into()))?;

        let mut actions = Vec::with_capacity(bb.actions.len());
        for a in bb.actions {
            let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&a.nf))
                .ok_or_else(|| ShieldedBundleError::Deserialize("invalid nullifier".into()))?;
            let rk = redpallas::VerificationKey::<SpendAuth>::try_from(a.rk)
                .map_err(|e| ShieldedBundleError::Deserialize(format!("invalid rk: {e:?}")))?;
            let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
                &a.cmx,
            ))
            .ok_or_else(|| ShieldedBundleError::Deserialize("invalid cmx".into()))?;
            let enc_ciphertext: [u8; 580] = a.enc_ciphertext.try_into().map_err(|_| {
                ShieldedBundleError::Deserialize("wrong enc_ciphertext length".into())
            })?;
            let out_ciphertext: [u8; 80] = a.out_ciphertext.try_into().map_err(|_| {
                ShieldedBundleError::Deserialize("wrong out_ciphertext length".into())
            })?;
            let encrypted_note = TransmittedNoteCiphertext {
                epk_bytes: a.epk_bytes,
                enc_ciphertext,
                out_ciphertext,
            };
            let cv_net = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&a.cv_net))
                .ok_or_else(|| ShieldedBundleError::Deserialize("invalid cv_net".into()))?;
            let spend_auth_sig: [u8; 64] = a.spend_auth_sig.try_into().map_err(|_| {
                ShieldedBundleError::Deserialize("wrong spend_auth_sig length".into())
            })?;
            let sig = redpallas::Signature::<SpendAuth>::from(spend_auth_sig);

            let action = Action::from_parts(nf, rk, cmx, encrypted_note, cv_net, sig)
                .map_err(|e| ShieldedBundleError::Deserialize(format!("invalid action: {e:?}")))?;
            actions.push(action);
        }
        let actions = NonEmpty::from_vec(actions).ok_or(ShieldedBundleError::Empty)?;

        let proof = Proof::new(bb.proof);
        let binding_signature_bytes: [u8; 64] = bb.binding_signature.try_into().map_err(|_| {
            ShieldedBundleError::Deserialize("wrong binding_signature length".into())
        })?;
        let binding_signature = redpallas::Signature::<Binding>::from(binding_signature_bytes);
        let authorization = Authorized::from_parts(proof, binding_signature);

        let bundle = Bundle::try_from_parts(
            actions,
            flags,
            bb.value_balance,
            anchor,
            authorization,
            bundle_version(),
        )
        .map_err(|e| ShieldedBundleError::Deserialize(format!("{e:?}")))?;
        Ok(ShieldedBundle(bundle))
    }
}

impl Serialize for ShieldedBundle {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        BundleBytes::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ShieldedBundle {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bb = BundleBytes::deserialize(deserializer)?;
        ShieldedBundle::try_from(bb).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::{Marking, Retention};
    use orchard::tree::MerkleHashOrchard;
    use orchard::value::NoteValue;
    use shardtree::store::memory::MemoryShardStore;
    use shardtree::ShardTree;

    /// Builds a single-leaf note commitment tree containing `cmx`, returning
    /// the tree's anchor and a Merkle witness for that leaf — enough to
    /// spend the note it corresponds to. Mirrors `orchard`'s own test helper
    /// of the same shape (see its `tests/builder.rs`).
    fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (Anchor, MerklePath) {
        let leaf = MerkleHashOrchard::from_cmx(cmx);
        let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
            ShardTree::new(MemoryShardStore::empty(), 100);
        tree.append(
            leaf,
            Retention::Checkpoint {
                id: 0,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
        let position = tree.max_leaf_position(None).unwrap().unwrap();
        let merkle_path = tree
            .witness_at_checkpoint_id(position, &0)
            .unwrap()
            .unwrap();
        (root.into(), merkle_path.into())
    }

    /// Full round trip: shield value into our own shielded address, discover
    /// the resulting note by local trial-decryption (exactly how a wallet
    /// scans for incoming payments), spend it in a private shielded-to-
    /// shielded transfer, verify the proof/signatures, and confirm the
    /// bundle survives a bincode serialize/deserialize round trip.
    ///
    /// This test genuinely builds Halo2 proving/verifying keys and creates
    /// two real zk-SNARK proofs, so it takes real wall-clock time (seconds,
    /// not milliseconds) — that's expected, not a bug; see `docs/PRIVACY.md`.
    #[test]
    fn shield_scan_spend_and_verify_round_trip() {
        let mnemonic = aeon_crypto::generate_mnemonic();
        let sk = crate::keys::derive_spending_key(&mnemonic, "");
        let fvk = crate::keys::full_viewing_key(&sk);
        let recipient = crate::keys::default_address(&sk);

        let shielding = build_shielding_bundle(recipient, 5000)
            .expect("shielding bundle should build, prove and sign");
        shielding.verify().expect("shielding bundle should verify");
        assert_eq!(shielding.value_balance(), -5000);

        let ivk = crate::keys::incoming_viewing_key(&fvk);
        let found = shielding.scan_for_incoming_notes(&ivk);
        assert_eq!(
            found.len(),
            1,
            "should discover exactly the one note addressed to us"
        );
        let (_, note, decrypted_to, _memo) = &found[0];
        assert_eq!(*decrypted_to, recipient);
        assert_eq!(note.value(), NoteValue::from_raw(5000));

        let cmx: ExtractedNoteCommitment = note.commitment().into();
        let (anchor, merkle_path) = single_leaf_witness(&cmx);
        let spend_auth_key = SpendAuthorizingKey::from(&sk);

        let spent = build_spend_bundle(
            fvk,
            &spend_auth_key,
            *note,
            merkle_path,
            anchor,
            &[(recipient, 5000)],
        )
        .expect("spend bundle should build, prove and sign");
        spent.verify().expect("spend bundle should verify");
        assert_eq!(
            spent.value_balance(),
            0,
            "a pure shielded-to-shielded transfer balances to zero"
        );
        // Every Orchard action pairs a spend and an output; with 1 real spend
        // and 1 real output the builder produces 2 actions total, pairing
        // each real half with a dummy counterpart — so there are 2
        // nullifiers here (1 real, 1 dummy), not 1. Recording every
        // nullifier, dummy or not, is what makes real and dummy spends
        // indistinguishable on-chain.
        assert_eq!(spent.nullifiers().len(), spent.inner().actions().len());

        let encoded = bincode::serialize(&spent).expect("bundle should serialize");
        let decoded: ShieldedBundle =
            bincode::deserialize(&encoded).expect("bundle should deserialize");
        decoded
            .verify()
            .expect("round-tripped bundle should still verify");
        assert_eq!(decoded.value_balance(), spent.value_balance());
        assert_eq!(decoded.nullifiers(), spent.nullifiers());
    }
}
