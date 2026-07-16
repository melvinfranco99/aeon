//! Difficulty target encoding and Aeon's difficulty adjustment algorithm
//! (DAA).
//!
//! Unlike Bitcoin (which retargets every 2016-block epoch), and faithfully
//! to Kaspa's design, Aeon retargets on **every single block** using a
//! sliding window of recent inter-block times. This is necessary at a
//! 1-block/second cadence, where waiting for a fixed epoch would let the
//! network drift far from the target before correcting.

use aeon_crypto::Hash;
use primitive_types::U256;

use crate::emission::TARGET_BLOCK_TIME_SECS;

/// The easiest possible target (lowest difficulty: 2^248 - 1, i.e. only the
/// top 8 bits of a header's BLAKE3 hash must be zero — about a 1-in-256
/// chance per try). Used for the genesis block; a lone CPU miner finds a
/// block almost instantly at this difficulty, which is what a new
/// hobby/test network needs, and the per-block DAA (see `next_bits`) pushes
/// difficulty up quickly once real mining starts.
pub fn max_target() -> U256 {
    (U256::one() << 248) - U256::one()
}

/// Number of most recent blocks (along the selected parent chain) used to
/// compute the next difficulty target.
pub const DAA_WINDOW_SIZE: usize = 60;

/// Maximum per-block adjustment factor in either direction, to damp
/// oscillation.
const MAX_ADJUSTMENT_FACTOR: f64 = 4.0;
const MIN_ADJUSTMENT_FACTOR: f64 = 1.0 / MAX_ADJUSTMENT_FACTOR;

/// Decodes a compact "nBits"-style difficulty encoding into a full 256-bit
/// target, using the same layout as Bitcoin: the top byte is a base-256
/// exponent, the remaining three bytes are the mantissa.
pub fn bits_to_target(bits: u32) -> U256 {
    let exponent = bits >> 24;
    let mantissa = bits & 0x007F_FFFF;
    if exponent <= 3 {
        U256::from(mantissa) >> (8 * (3 - exponent))
    } else {
        U256::from(mantissa) << (8 * (exponent - 3))
    }
}

/// Encodes a 256-bit target into the compact "nBits" representation.
pub fn target_to_bits(target: U256) -> u32 {
    let mut bytes = [0u8; 32];
    target.to_big_endian(&mut bytes);
    let first_nonzero = bytes.iter().position(|&b| b != 0);
    let Some(first_nonzero) = first_nonzero else {
        return 0;
    };
    let significant = &bytes[first_nonzero..];
    let mut exponent = (32 - first_nonzero) as u32;
    let mut mantissa_bytes = [0u8; 3];
    if significant.len() >= 3 {
        mantissa_bytes.copy_from_slice(&significant[0..3]);
    } else {
        mantissa_bytes[..significant.len()].copy_from_slice(significant);
    }
    // If the top bit of the mantissa is set it would be misread as a sign
    // bit; shift right by one byte and bump the exponent, as Bitcoin does.
    if mantissa_bytes[0] & 0x80 != 0 {
        mantissa_bytes = [0, mantissa_bytes[0], mantissa_bytes[1]];
        exponent += 1;
    }
    let mantissa = u32::from_be_bytes([0, mantissa_bytes[0], mantissa_bytes[1], mantissa_bytes[2]]);
    (exponent << 24) | mantissa
}

pub fn hash_meets_target(hash: &Hash, target: U256) -> bool {
    U256::from_big_endian(hash.as_bytes()) <= target
}

/// The proof-of-work "work" contributed by a block with the given target:
/// approximately `2^256 / (target + 1)`, the same quantity Bitcoin calls
/// "chainwork". Used to accumulate `blue_work` in the GHOSTDAG engine.
/// Saturates at `u128::MAX` for extremely low (hard) targets, which cannot
/// occur in practice long before `u128` would overflow.
pub fn work_from_target(target: U256) -> u128 {
    let denominator = target.saturating_add(U256::one());
    let quotient = U256::max_value() / denominator;
    if quotient > U256::from(u128::MAX) {
        u128::MAX
    } else {
        quotient.as_u128()
    }
}

pub fn genesis_bits() -> u32 {
    target_to_bits(max_target())
}

/// One data point the DAA needs about each recent block.
#[derive(Clone, Copy, Debug)]
pub struct DaaWindowEntry {
    pub timestamp: u64,
    pub bits: u32,
}

/// Computes the difficulty target for the next block, given a window of
/// recent blocks ordered oldest-first with the most recent block last.
///
/// The rule: compare the actual elapsed time across the window to the
/// expected time at 1 block/second, and scale the *average* target of the
/// window by that ratio (higher ratio = blocks arriving slower than
/// expected = easier target). The per-step adjustment is clamped to
/// [0.25x, 4x] to prevent oscillation/instability.
pub fn next_bits(window: &[DaaWindowEntry]) -> u32 {
    if window.len() < 2 {
        return window.first().map(|e| e.bits).unwrap_or_else(genesis_bits);
    }

    let oldest = window.first().unwrap();
    let newest = window.last().unwrap();
    let actual_span = newest.timestamp.saturating_sub(oldest.timestamp).max(1);
    let expected_span = TARGET_BLOCK_TIME_SECS * (window.len() as u64 - 1);

    let avg_target = average_target(window);

    let mut ratio = actual_span as f64 / expected_span as f64;
    ratio = ratio.clamp(MIN_ADJUSTMENT_FACTOR, MAX_ADJUSTMENT_FACTOR);

    let new_target = scale_target(avg_target, ratio);
    let clamped = new_target.min(max_target());
    target_to_bits(clamped)
}

fn average_target(window: &[DaaWindowEntry]) -> U256 {
    let mut sum = U256::zero();
    for entry in window {
        sum += bits_to_target(entry.bits);
    }
    sum / U256::from(window.len() as u64)
}

/// Scales a U256 target by a floating-point ratio, representing the ratio
/// as a small rational `numerator / SCALE` rather than a large fixed-point
/// multiplier. `target` can be as large as `max_target()` (close to the
/// full 256-bit range), so we divide by `SCALE` *before* multiplying by
/// `numerator` — the reverse order would overflow U256 for large targets.
/// This costs a little precision (a relative error on the order of
/// `1/SCALE`), which is unimportant for a difficulty retarget.
fn scale_target(target: U256, ratio: f64) -> U256 {
    const SCALE: u64 = 1024;
    let numerator = (ratio * SCALE as f64)
        .round()
        .clamp(1.0, (SCALE * MAX_ADJUSTMENT_FACTOR as u64) as f64) as u64;
    (target / U256::from(SCALE)) * U256::from(numerator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_target_roundtrip_is_stable() {
        for bits in [genesis_bits(), 0x1d00ffff, 0x1b0404cb] {
            let target = bits_to_target(bits);
            let re_encoded = target_to_bits(target);
            let re_decoded = bits_to_target(re_encoded);
            assert_eq!(target, re_decoded, "bits=0x{bits:08x}");
        }
    }

    #[test]
    fn stable_block_times_keep_difficulty_unchanged() {
        let bits = genesis_bits();
        let window: Vec<_> = (0..DAA_WINDOW_SIZE as u64)
            .map(|i| DaaWindowEntry {
                timestamp: i * TARGET_BLOCK_TIME_SECS,
                bits,
            })
            .collect();
        let next = next_bits(&window);
        // Already at the easiest allowed target with on-time blocks, so it
        // should stay (almost exactly) the same: `scale_target` trades a
        // little precision (see its doc comment) to avoid overflowing on
        // very large targets, so we check closeness rather than exact
        // equality.
        let original = bits_to_target(bits);
        let result = bits_to_target(next);
        assert!(result <= original);
        // original and result are both close to 2^248, far beyond u128, so
        // compare relative error using U256 arithmetic directly rather
        // than converting to a float: (original - result) / original < 1%.
        let diff = original - result;
        assert!(
            diff * U256::from(100u32) <= original,
            "target drifted by more than 1%: {original} -> {result}"
        );
    }

    #[test]
    fn faster_than_target_blocks_increase_difficulty() {
        let easy_bits = target_to_bits(max_target() >> 8); // harder than max_target()
        let window: Vec<_> = (0..DAA_WINDOW_SIZE as u64)
            .map(|i| DaaWindowEntry {
                // blocks arriving 4x faster than the 1s target
                timestamp: i * TARGET_BLOCK_TIME_SECS / 4,
                bits: easy_bits,
            })
            .collect();
        let next = next_bits(&window);
        assert!(
            bits_to_target(next) < bits_to_target(easy_bits),
            "target should shrink (difficulty should rise) when blocks come in faster than expected"
        );
    }

    #[test]
    fn harder_target_yields_more_work() {
        let easy = max_target();
        let hard = max_target() >> 4;
        assert!(work_from_target(hard) > work_from_target(easy));
    }

    #[test]
    fn slower_than_target_blocks_decrease_difficulty() {
        let bits = target_to_bits(max_target() >> 8);
        let window: Vec<_> = (0..DAA_WINDOW_SIZE as u64)
            .map(|i| DaaWindowEntry {
                timestamp: i * TARGET_BLOCK_TIME_SECS * 4,
                bits,
            })
            .collect();
        let next = next_bits(&window);
        assert!(
            bits_to_target(next) > bits_to_target(bits),
            "target should grow (difficulty should fall) when blocks come in slower than expected"
        );
    }
}
