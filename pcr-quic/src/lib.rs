//! # PCR-QUIC: Double Ratchet Protocol for QUIC
//!
//! This crate implements a double ratchet protocol providing:
//! - **Forward Secrecy (FS)**: Per-packet nonce ratchet
//! - **Post-Compromise Security (PCS)**: KEM-based epoch rekey
//! - **Precise Key Deletion**: Cryptographic key zeroization
//!
//! ## Architecture
//!
//! PCR-QUIC operates with two ratchet layers:
//!
//! 1. **Epoch Ratchet**: KEM-based rekey (~2 minutes)
//!    - Hybrid X25519 + ML-KEM-768 key exchange
//!    - Derives per-direction AES-256-GCM keys
//!
//! 2. **Per-Packet Ratchet**: BLAKE3-based nonce derivation
//!    - Computes nonce from packet number and epoch state
//!    - Forward-secure nonce key deletion

use std::fmt;

// ============================================================================
// Error Types (defined first so From impls are available to all modules)
// ============================================================================

/// PCR-QUIC error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcrError {
    /// Cryptographic operation failed
    CryptoFailed,
    
    /// Buffer too small for operation
    BufferTooShort,
    
    /// Invalid packet number
    InvalidPacketNumber,
    
    /// Epoch not found
    EpochNotFound,
    
    /// Invalid frame format
    InvalidFrame,
    
    /// Done processing (not an error)
    Done,
    
    /// Invalid state transition
    InvalidState,
    
    /// KEM operation failed
    KemFailed,
    
    /// HKDF operation failed
    HkdfFailed,
    
    /// AEAD operation failed
    AeadFailed,
    
    /// Packet decryption failed (authentication)
    DecryptionFailed,
    
    /// Generic error with message
    Other(String),
}

impl fmt::Display for PcrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcrError::CryptoFailed => write!(f, "Cryptographic operation failed"),
            PcrError::BufferTooShort => write!(f, "Buffer too short"),
            PcrError::InvalidPacketNumber => write!(f, "Invalid packet number"),
            PcrError::EpochNotFound => write!(f, "Epoch not found"),
            PcrError::InvalidFrame => write!(f, "Invalid frame format"),
            PcrError::Done => write!(f, "Done"),
            PcrError::InvalidState => write!(f, "Invalid state"),
            PcrError::KemFailed => write!(f, "KEM operation failed"),
            PcrError::HkdfFailed => write!(f, "HKDF operation failed"),
            PcrError::AeadFailed => write!(f, "AEAD operation failed"),
            PcrError::DecryptionFailed => write!(f, "Packet decryption failed"),
            PcrError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for PcrError {}

/// Result type for PCR-QUIC operations
pub type Result<T> = std::result::Result<T, PcrError>;

// ============================================================================
// Modules
// ============================================================================

pub mod pcr_shim;
pub mod keys;
pub mod ratchet;
pub mod context;
pub mod params;
pub mod frame;

// ============================================================================
// Re-exports
// ============================================================================

pub use context::PcrCryptoContext;
pub use frame::{PcrRekeyFrame, PcrRekeyAckFrame, PCR_REKEY_FRAME_TYPE, PCR_REKEY_ACK_FRAME_TYPE};
pub use keys::{Direction, Epoch, EpochKeys, derive_epoch_keys};
pub use params::{KemId, NegotiatedPcrParams, PcrTransportParam, PCR_QUIC_TP_ID};
pub use ratchet::{PcrPacketKey, seal_packet, open_packet, compute_nonce, DEFAULT_SKIP_WINDOW};
