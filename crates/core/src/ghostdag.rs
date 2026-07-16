//! The GHOSTDAG consensus engine: coloring blocks blue/red, scoring them,
//! and selecting the "selected tip" of the BlockDAG.
//!
//! This follows the coloring/scoring rules from the GHOSTDAG paper
//! (Sompolinsky, Wyborski, Zohar) and Kaspa's implementation of it:
//!
//! - Every block picks a **selected parent**: the parent with the greatest
//!   `blue_work` (ties broken by the smaller hash).
//! - Its **merge set** is every other ancestor reachable from its parents
//!   that isn't already in the selected parent's past.
//! - Merge set blocks are colored **blue** if adding them keeps every
//!   pairwise anticone within the growing blue set at most `k` (the
//!   security parameter); otherwise they're colored **red**.
//! - `blue_score` / `blue_work` accumulate along the selected-parent chain,
//!   and only blue blocks' proof-of-work counts towards `blue_work` — this
//!   is what makes GHOSTDAG resistant to attackers who withhold blocks.
//!
//! **Scope note:** reachability (`is_ancestor`) is answered here by walking
//! the selected-parent chain and each block's recorded merge sets, pruning
//! once blue scores drop below the target. This is simpler than the
//! interval-tree reachability index Kaspa uses in production to serve those
//! queries in ~O(1) on massive DAGs, but is fully correct, and its
//! O(blue_score delta) cost is negligible for a small/hobby network. The
//! blue/red decision below also only re-checks the *candidate's* anticone
//! size against the current blue set; the full GHOSTDAG spec additionally
//! re-validates that accepting a candidate doesn't push an already-blue
//! block over `k`, which matters only under heavy parallelism far beyond
//! what a small network produces. Both simplifications are noted in
//! `docs/CONSENSUS.md`.

use std::collections::{HashSet, VecDeque};

use aeon_crypto::Hash;
use serde::{Deserialize, Serialize};

/// Consensus-critical GHOSTDAG parameters.
#[derive(Clone, Copy, Debug)]
pub struct GhostdagParams {
    /// Maximum anticone size tolerated within the blue set. Higher values
    /// tolerate more network latency/parallelism at the cost of slower
    /// finality; Kaspa's own mainnet historically used values in this
    /// range for a 1 block/second target.
    pub k: u32,
}

impl Default for GhostdagParams {
    fn default() -> Self {
        GhostdagParams { k: 18 }
    }
}

/// Derived GHOSTDAG bookkeeping for a single block. Computed deterministically
/// by every honest node from the DAG structure; not itself part of the
/// block header.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GhostdagData {
    pub selected_parent: Option<Hash>,
    pub mergeset_blues: Vec<Hash>,
    pub mergeset_reds: Vec<Hash>,
    pub blue_score: u64,
    pub blue_work: u128,
}

impl GhostdagData {
    pub fn genesis() -> Self {
        GhostdagData {
            selected_parent: None,
            mergeset_blues: vec![],
            mergeset_reds: vec![],
            blue_score: 0,
            blue_work: 0,
        }
    }
}

/// Read-only access to already-processed ancestors, needed to compute a new
/// block's GHOSTDAG data. Implemented in-memory for tests and by
/// `aeon-storage` for the real, persistent node.
pub trait GhostdagStore {
    fn parents(&self, block: &Hash) -> Vec<Hash>;
    fn ghostdag_data(&self, block: &Hash) -> Option<GhostdagData>;
    /// Proof-of-work "work" contributed by this single block (derived from
    /// its difficulty target: work = 2^256 / (target + 1)).
    fn header_work(&self, block: &Hash) -> u128;
}

/// Computes the GHOSTDAG data for a new block given its parents. All
/// parents must already be known to `store` (i.e. processed).
///
/// `own_work` is the new block's own proof-of-work contribution (see
/// `aeon_core::work_from_target`), passed explicitly rather than looked up
/// via `store.header_work` so that callers can compute a candidate block's
/// GHOSTDAG data — in particular its `blue_score`, needed to validate the
/// coinbase reward — *before* persisting the block anywhere.
pub fn compute_ghostdag_data<S: GhostdagStore>(
    store: &S,
    _block_hash: &Hash,
    parents: &[Hash],
    own_work: u128,
    params: &GhostdagParams,
) -> GhostdagData {
    assert!(
        !parents.is_empty(),
        "only the genesis block may have no parents"
    );

    let selected_parent = select_parent(store, parents);

    let candidates = mergeset_candidates(store, parents, &selected_parent);
    let ordered = order_candidates(store, candidates);

    let mut blue_set = materialize_recent_blue_set(store, &selected_parent, params);
    blue_set.insert(selected_parent);

    let mut mergeset_blues = Vec::new();
    let mut mergeset_reds = Vec::new();
    for candidate in ordered {
        let anticone_size = blue_set
            .iter()
            .filter(|blue| {
                **blue != candidate
                    && !is_ancestor(store, blue, &candidate)
                    && !is_ancestor(store, &candidate, blue)
            })
            .count();
        if anticone_size as u32 <= params.k {
            mergeset_blues.push(candidate);
            blue_set.insert(candidate);
        } else {
            mergeset_reds.push(candidate);
        }
    }

    let parent_data = store
        .ghostdag_data(&selected_parent)
        .expect("selected parent must already be processed");
    let mergeset_blue_work: u128 = mergeset_blues.iter().map(|h| store.header_work(h)).sum();

    GhostdagData {
        selected_parent: Some(selected_parent),
        blue_score: parent_data.blue_score + 1 + mergeset_blues.len() as u64,
        blue_work: parent_data.blue_work + own_work + mergeset_blue_work,
        mergeset_blues,
        mergeset_reds,
    }
}

fn select_parent<S: GhostdagStore>(store: &S, parents: &[Hash]) -> Hash {
    *parents
        .iter()
        .max_by(|a, b| {
            let da = store.ghostdag_data(a).expect("parent must be processed");
            let db = store.ghostdag_data(b).expect("parent must be processed");
            // Higher blue_work wins; ties broken by *smaller* hash, so we
            // reverse the hash comparison before feeding max_by.
            da.blue_work.cmp(&db.blue_work).then_with(|| b.cmp(a))
        })
        .expect("parents is non-empty")
}

/// Every block reachable from a non-selected parent that is not already in
/// the selected parent's past.
fn mergeset_candidates<S: GhostdagStore>(
    store: &S,
    parents: &[Hash],
    selected_parent: &Hash,
) -> Vec<Hash> {
    let mut visited = HashSet::new();
    let mut candidates = Vec::new();
    let mut queue: VecDeque<Hash> = parents
        .iter()
        .filter(|p| *p != selected_parent)
        .copied()
        .collect();

    while let Some(h) = queue.pop_front() {
        if h == *selected_parent || visited.contains(&h) {
            continue;
        }
        if is_ancestor(store, &h, selected_parent) {
            continue;
        }
        visited.insert(h);
        candidates.push(h);
        for parent in store.parents(&h) {
            queue.push_back(parent);
        }
    }
    candidates
}

/// Orders merge-set candidates topologically (ascending blue score, tie
/// broken by hash) so blue/red coloring is processed consistently by every
/// node.
fn order_candidates<S: GhostdagStore>(store: &S, mut candidates: Vec<Hash>) -> Vec<Hash> {
    candidates.sort_by(|a, b| {
        let da = store.ghostdag_data(a).expect("candidate must be processed");
        let db = store.ghostdag_data(b).expect("candidate must be processed");
        da.blue_score.cmp(&db.blue_score).then_with(|| a.cmp(b))
    });
    candidates
}

/// How many blue blocks (going back from `tip` along its selected-parent
/// chain) to materialize when checking anticone sizes. Blocks further back
/// than this are, by the k-cluster locality assumption, always ancestors of
/// every current merge-set candidate and thus irrelevant to the anticone
/// count.
fn recent_blue_window_size(params: &GhostdagParams) -> usize {
    (params.k as usize + 1) * 20
}

fn materialize_recent_blue_set<S: GhostdagStore>(
    store: &S,
    tip: &Hash,
    params: &GhostdagParams,
) -> HashSet<Hash> {
    let mut set = HashSet::new();
    let mut current = *tip;
    for _ in 0..recent_blue_window_size(params) {
        set.insert(current);
        let Some(data) = store.ghostdag_data(&current) else {
            break;
        };
        for blue in &data.mergeset_blues {
            set.insert(*blue);
        }
        match data.selected_parent {
            Some(sp) => current = sp,
            None => break,
        }
    }
    set
}

/// Whether `x` is an ancestor of (or equal to) `y`, answered by walking `y`'s
/// selected-parent chain and each visited block's recorded merge sets. See
/// the module-level scope note about complexity.
pub fn is_ancestor<S: GhostdagStore>(store: &S, x: &Hash, y: &Hash) -> bool {
    if x == y {
        return true;
    }
    let Some(x_data) = store.ghostdag_data(x) else {
        return false;
    };
    let mut current = *y;
    loop {
        let Some(data) = store.ghostdag_data(&current) else {
            return false;
        };
        if data.mergeset_blues.contains(x) || data.mergeset_reds.contains(x) {
            return true;
        }
        let Some(sp) = data.selected_parent else {
            return false;
        };
        if sp == *x {
            return true;
        }
        let sp_data = store
            .ghostdag_data(&sp)
            .expect("selected parent must be processed");
        if sp_data.blue_score < x_data.blue_score {
            return false;
        }
        current = sp;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A trivial in-memory DAG used to unit test the coloring rules against
    /// hand-built topologies.
    #[derive(Default)]
    struct TestDag {
        parents: HashMap<Hash, Vec<Hash>>,
        data: HashMap<Hash, GhostdagData>,
        work: HashMap<Hash, u128>,
    }

    impl GhostdagStore for TestDag {
        fn parents(&self, block: &Hash) -> Vec<Hash> {
            self.parents.get(block).cloned().unwrap_or_default()
        }
        fn ghostdag_data(&self, block: &Hash) -> Option<GhostdagData> {
            self.data.get(block).cloned()
        }
        fn header_work(&self, block: &Hash) -> u128 {
            *self.work.get(block).unwrap_or(&1)
        }
    }

    fn h(byte: u8) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        Hash::from(bytes)
    }

    impl TestDag {
        fn add_genesis(&mut self, block: Hash) {
            self.parents.insert(block, vec![]);
            self.data.insert(block, GhostdagData::genesis());
            self.work.insert(block, 1);
        }

        fn add_block(&mut self, block: Hash, parents: Vec<Hash>, params: &GhostdagParams) {
            self.parents.insert(block, parents.clone());
            self.work.insert(block, 1);
            let data = compute_ghostdag_data(self, &block, &parents, 1, params);
            self.data.insert(block, data);
        }
    }

    #[test]
    fn linear_chain_has_monotonically_increasing_blue_score() {
        let params = GhostdagParams::default();
        let mut dag = TestDag::default();
        let genesis = h(0);
        dag.add_genesis(genesis);

        let mut prev = genesis;
        for i in 1..=10u8 {
            let block = h(i);
            dag.add_block(block, vec![prev], &params);
            prev = block;
        }

        let tip_data = dag.ghostdag_data(&prev).unwrap();
        assert_eq!(tip_data.blue_score, 10);
        assert!(tip_data.mergeset_reds.is_empty());
    }

    #[test]
    fn parallel_blocks_within_k_are_all_colored_blue() {
        let params = GhostdagParams { k: 3 };
        let mut dag = TestDag::default();
        let genesis = h(0);
        dag.add_genesis(genesis);

        // Three blocks mined in parallel off genesis.
        let a = h(1);
        let b = h(2);
        let c = h(3);
        dag.add_block(a, vec![genesis], &params);
        dag.add_block(b, vec![genesis], &params);
        dag.add_block(c, vec![genesis], &params);

        // A block that merges all three parallel tips.
        let merger = h(4);
        dag.add_block(merger, vec![a, b, c], &params);

        let data = dag.ghostdag_data(&merger).unwrap();
        // selected parent is one of {a,b,c} (equal blue_work, tie-break by
        // hash), and the other two land in its merge set.
        assert_eq!(data.mergeset_blues.len(), 2);
        assert!(data.mergeset_reds.is_empty());
        assert_eq!(
            data.blue_score,
            1 /*selected parent*/ + 1 /*merger itself*/ + 2 /*merged blues*/
        );
    }

    #[test]
    fn anticone_larger_than_k_is_colored_red() {
        let params = GhostdagParams { k: 1 };
        let mut dag = TestDag::default();
        let genesis = h(0);
        dag.add_genesis(genesis);

        // Four parallel blocks off genesis: with k=1, only 2 total blues
        // (including the selected parent) can be mutually non-ancestor.
        let parallel: Vec<Hash> = (1..=4u8).map(h).collect();
        for p in &parallel {
            dag.add_block(*p, vec![genesis], &params);
        }

        let merger = h(5);
        dag.add_block(merger, parallel.clone(), &params);

        let data = dag.ghostdag_data(&merger).unwrap();
        // With k=1 the selected parent can tolerate at most 1 other
        // mutually-anticone blue block before further candidates must turn
        // red (their anticone within the blue set would exceed k=1).
        assert!(
            !data.mergeset_reds.is_empty(),
            "some candidates must be red when anticone exceeds k"
        );
        assert!(data.mergeset_blues.len() <= 2);
    }

    #[test]
    fn is_ancestor_true_for_direct_and_transitive_parents() {
        let params = GhostdagParams::default();
        let mut dag = TestDag::default();
        let genesis = h(0);
        dag.add_genesis(genesis);
        let a = h(1);
        let b = h(2);
        dag.add_block(a, vec![genesis], &params);
        dag.add_block(b, vec![a], &params);

        assert!(is_ancestor(&dag, &genesis, &b));
        assert!(is_ancestor(&dag, &a, &b));
        assert!(!is_ancestor(&dag, &b, &a));
    }

    #[test]
    fn is_ancestor_false_for_unrelated_parallel_blocks() {
        let params = GhostdagParams::default();
        let mut dag = TestDag::default();
        let genesis = h(0);
        dag.add_genesis(genesis);
        let a = h(1);
        let b = h(2);
        dag.add_block(a, vec![genesis], &params);
        dag.add_block(b, vec![genesis], &params);

        assert!(!is_ancestor(&dag, &a, &b));
        assert!(!is_ancestor(&dag, &b, &a));
    }

    #[test]
    fn only_blue_blocks_work_counts_towards_blue_work() {
        let params = GhostdagParams { k: 0 };
        let mut dag = TestDag::default();
        let genesis = h(0);
        dag.add_genesis(genesis);

        // Two parallel blocks; with k=0 only the selected parent stays
        // blue, the other becomes red.
        let a = h(1);
        let b = h(2);
        dag.add_block(a, vec![genesis], &params);
        dag.add_block(b, vec![genesis], &params);

        let merger = h(3);
        dag.add_block(merger, vec![a, b], &params);
        let data = dag.ghostdag_data(&merger).unwrap();

        assert_eq!(data.mergeset_blues.len(), 0);
        assert_eq!(data.mergeset_reds.len(), 1);
        // blue_work = selected_parent's blue_work + merger's own work only
        // (the red block's work of 1 is excluded).
        let sp_work = dag
            .ghostdag_data(&data.selected_parent.unwrap())
            .unwrap()
            .blue_work;
        assert_eq!(data.blue_work, sp_work + 1);
    }
}
