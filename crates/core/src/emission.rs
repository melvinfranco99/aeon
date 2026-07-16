//! Aeon's monetary policy.
//!
//! Aeon reuses Bitcoin's exact issuance *mechanism* (an integer block reward
//! that halves every fixed number of blocks, floored by right-shifting)
//! rather than Bitcoin's specific numbers: reusing Bitcoin's 50-coin reward
//! together with its 210,000-block halving interval would, at Aeon's much
//! faster 1-block/second cadence, exhaust the supply in about 80 days
//! instead of over a century. Both free parameters (initial reward,
//! halving interval) are instead solved together so that, simultaneously:
//!
//! 1. the total supply converges to (just under) 21,000,000 AEON, exactly
//!    like Bitcoin's own 20,999,999.9769... BTC asymptote, and
//! 2. the reward reaches exactly zero (full emission) roughly 114 years
//!    after genesis — i.e. around the year 2140 for a ~2026 genesis, on the
//!    same *timeline* as Bitcoin even though the block-level mechanics
//!    differ.
//!
//! See `total_supply_converges_to_21_million_and_reward_hits_zero` and
//! `timeline_lands_around_the_year_2140` below for the simulation that
//! verifies both properties hold for the chosen constants.

/// Smallest indivisible unit of AEON, named `quark` (analogous to Bitcoin's
/// satoshi). 1 AEON = 100_000_000 quarks (8 decimals).
pub const QUARKS_PER_AEON: u64 = 100_000_000;

/// Block reward paid to the miner for chain height 0, in quarks
/// (0.067 AEON). Solved jointly with [`HALVING_INTERVAL_BLOCKS`] so the
/// schedule hits both the 21,000,000 AEON supply cap and the ~2140
/// exhaustion year at a 1-block/second cadence.
pub const INITIAL_REWARD_QUARKS: u64 = 6_700_000;

/// Number of blocks between each halving (~4.97 years at the 1
/// block/second target).
pub const HALVING_INTERVAL_BLOCKS: u64 = 156_716_418;

/// Target block interval, in seconds, that the difficulty adjustment
/// algorithm converges towards (Kaspa's original mainnet cadence).
pub const TARGET_BLOCK_TIME_SECS: u64 = 1;

/// Maximum possible supply, in quarks. The emission schedule asymptotically
/// approaches this value from below (it is never reached exactly, mirroring
/// Bitcoin's own real max supply of 20,999,999.9769... BTC rather than a
/// clean 21,000,000).
pub const MAX_SUPPLY_QUARKS: u64 = 21_000_000 * QUARKS_PER_AEON;

/// Approximate calendar year Aeon's genesis block is expected to be mined.
/// Used only for documentation/derived estimates, not for consensus.
pub const GENESIS_YEAR_ESTIMATE: u32 = 2026;

/// The block reward (in quarks) for a block at the given height along the
/// selected parent chain (Aeon's GHOSTDAG analogue of Bitcoin's "chain
/// height"; see `ghostdag::GhostdagData::blue_score`).
///
/// Mirrors Bitcoin's `GetBlockSubsidy`: the reward is right-shifted by one
/// bit per halving epoch, so it naturally reaches exactly zero once the
/// shift exceeds the reward's bit width, rather than needing a
/// special-cased cutoff.
pub fn block_reward(chain_height: u64) -> u64 {
    let halvings = chain_height / HALVING_INTERVAL_BLOCKS;
    if halvings >= 64 {
        0
    } else {
        INITIAL_REWARD_QUARKS >> halvings
    }
}

/// The halving epoch (0-indexed) for a given chain height.
pub fn halving_epoch(chain_height: u64) -> u64 {
    chain_height / HALVING_INTERVAL_BLOCKS
}

/// The halving epoch at which the reward first reaches zero (i.e. the
/// number of epochs that actually pay out a nonzero reward).
pub fn final_halving_epoch() -> u64 {
    let mut epoch = 0u64;
    while block_reward(epoch * HALVING_INTERVAL_BLOCKS) != 0 {
        epoch += 1;
    }
    epoch
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simulates the full emission schedule epoch-by-epoch (not block by
    /// block, which would require simulating billions of blocks) and checks
    /// that the total supply converges to just under 21,000,000 AEON.
    #[test]
    fn total_supply_converges_to_21_million_and_reward_hits_zero() {
        let final_epoch = final_halving_epoch();
        let mut total_quarks: u128 = 0;

        for epoch in 0..final_epoch {
            let reward = block_reward(epoch * HALVING_INTERVAL_BLOCKS);
            assert_ne!(reward, 0);
            total_quarks += reward as u128 * HALVING_INTERVAL_BLOCKS as u128;
        }
        assert_eq!(block_reward(final_epoch * HALVING_INTERVAL_BLOCKS), 0);

        assert!(
            total_quarks <= MAX_SUPPLY_QUARKS as u128,
            "must never exceed the cap"
        );

        // The rounding "dust" lost to integer division across every halving
        // should be a small fraction of the cap, just as Bitcoin's real
        // supply falls a little short of a clean 21,000,000 BTC.
        let shortfall = MAX_SUPPLY_QUARKS as u128 - total_quarks;
        let shortfall_ratio = shortfall as f64 / MAX_SUPPLY_QUARKS as f64;
        assert!(
            shortfall_ratio < 0.01,
            "shortfall ratio {shortfall_ratio} should be under 1%"
        );
    }

    #[test]
    fn timeline_lands_around_the_year_2140() {
        let final_epoch = final_halving_epoch();
        let seconds_to_exhaustion = final_epoch * HALVING_INTERVAL_BLOCKS * TARGET_BLOCK_TIME_SECS;
        let years_to_exhaustion = seconds_to_exhaustion as f64 / (365.25 * 86_400.0);
        let exhaustion_year = GENESIS_YEAR_ESTIMATE as f64 + years_to_exhaustion;

        assert!(
            (2138.0..=2142.0).contains(&exhaustion_year),
            "expected exhaustion around 2140, got {exhaustion_year} (final_epoch={final_epoch})"
        );
    }

    #[test]
    fn reward_halves_at_each_epoch_boundary() {
        assert_eq!(block_reward(0), INITIAL_REWARD_QUARKS);
        assert_eq!(
            block_reward(HALVING_INTERVAL_BLOCKS - 1),
            INITIAL_REWARD_QUARKS
        );
        assert_eq!(
            block_reward(HALVING_INTERVAL_BLOCKS),
            INITIAL_REWARD_QUARKS / 2
        );
        assert_eq!(
            block_reward(2 * HALVING_INTERVAL_BLOCKS),
            INITIAL_REWARD_QUARKS / 4
        );
    }
}
