//! Aeon's optional shielded (private) transaction pool.
//!
//! This crate wraps Zcash's real, audited `orchard` protocol (Halo2-based
//! zk-SNARKs, no trusted setup) rather than implementing any zero-knowledge
//! cryptography from scratch — see `docs/PRIVACY.md` for why that matters.

pub mod bundle;
pub mod keys;
pub mod tree;

pub use bundle::{build_shielding_bundle, build_spend_bundle, ShieldedBundle, ShieldedBundleError};
pub use keys::{
    decode_address, default_address, derive_spending_key, derive_spending_key_from_seed,
    encode_address, full_viewing_key, incoming_viewing_key, ShieldedAddressError,
};
pub use orchard;
pub use tree::{witness_for_position, CommitmentFrontier};
