//! PCR-QUIC Transport Parameter
//!
//! Defines the `pcr_quic` transport parameter for negotiating PCR mode
//! between QUIC endpoints.
//!
//! # Wire Format
//!
//! ```text
//! PCR-QUIC Transport Parameter {
//!     Version (8),
//!     KEM ID (16),
//!     Rekey Interval (32),    // seconds
//!     Window W (32),          // max out-of-order packets
//! }
//! ```
//!
//! # Negotiation
//!
//! PCR mode is enabled only when both peers advertise the `pcr_quic`
//! transport parameter with compatible versions and KEM IDs.

use crate::{PcrError, Result};

/// PCR-QUIC transport parameter ID (private-use range: 0x41 + 0x1f * N)
/// Using 0xff00 + 'P' (0x50) + 'C' (0x43) + 'R' (0x52) = 0xff0050435200
/// Simplified to a private-use varint: 0xff000001 (arbitrary choice in private range)
pub const PCR_QUIC_TP_ID: u64 = 0xff000001;

/// Current PCR-QUIC protocol version
pub const PCR_VERSION: u8 = 0x01;

/// KEM algorithm identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum KemId {
    /// X25519 only (fallback, no post-quantum)
    X25519 = 0x0020,
    /// X25519 + ML-KEM-768 hybrid
    X25519MlKem768 = 0x0100,
}

impl KemId {
    /// Parse KEM ID from u16
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0020 => Some(KemId::X25519),
            0x0100 => Some(KemId::X25519MlKem768),
            _ => None,
        }
    }

    /// Get ciphertext length for this KEM
    pub fn ciphertext_len(&self) -> usize {
        match self {
            KemId::X25519 => 32,
            KemId::X25519MlKem768 => 32 + 1088, // X25519 ephemeral + ML-KEM-768 ct
        }
    }

    /// Get public key length for this KEM
    pub fn public_key_len(&self) -> usize {
        match self {
            KemId::X25519 => 32,
            KemId::X25519MlKem768 => 32 + 1184, // X25519 + ML-KEM-768 pk
        }
    }

    /// Get secret key length for this KEM
    pub fn secret_key_len(&self) -> usize {
        match self {
            KemId::X25519 => 32,
            KemId::X25519MlKem768 => 32 + 2400, // X25519 + ML-KEM-768 sk
        }
    }
}

impl Default for KemId {
    fn default() -> Self {
        KemId::X25519MlKem768
    }
}

/// PCR-QUIC transport parameter contents
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrTransportParam {
    /// Protocol version
    pub version: u8,
    /// KEM algorithm ID
    pub kem_id: KemId,
    /// Rekey interval in seconds (default: 120 = 2 minutes)
    pub rekey_interval_secs: u32,
    /// Maximum out-of-order window for packet decryption
    pub window: u32,
}

impl Default for PcrTransportParam {
    fn default() -> Self {
        Self {
            version: PCR_VERSION,
            kem_id: KemId::default(),
            rekey_interval_secs: 120, // 2 minutes
            window: 512,
        }
    }
}

impl PcrTransportParam {
    /// Create a new PCR transport parameter with custom values
    pub fn new(kem_id: KemId, rekey_interval_secs: u32, window: u32) -> Self {
        Self {
            version: PCR_VERSION,
            kem_id,
            rekey_interval_secs,
            window,
        }
    }

    /// Encode the transport parameter to bytes
    ///
    /// Returns the encoded parameter value (not including TP ID/length framing)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(11);
        buf.push(self.version);
        buf.extend_from_slice(&(self.kem_id as u16).to_be_bytes());
        buf.extend_from_slice(&self.rekey_interval_secs.to_be_bytes());
        buf.extend_from_slice(&self.window.to_be_bytes());
        buf
    }

    /// Decode the transport parameter from bytes
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 11 {
            return Err(PcrError::InvalidFrame);
        }

        let version = buf[0];
        if version != PCR_VERSION {
            return Err(PcrError::InvalidFrame);
        }

        let kem_id_raw = u16::from_be_bytes([buf[1], buf[2]]);
        let kem_id = KemId::from_u16(kem_id_raw)
            .ok_or(PcrError::InvalidFrame)?;

        let rekey_interval_secs = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]);
        let window = u32::from_be_bytes([buf[7], buf[8], buf[9], buf[10]]);

        // Validate ranges
        if rekey_interval_secs == 0 || window == 0 {
            return Err(PcrError::InvalidFrame);
        }

        Ok(Self {
            version,
            kem_id,
            rekey_interval_secs,
            window,
        })
    }

    /// Check if two transport parameters are compatible for negotiation
    pub fn is_compatible(&self, other: &Self) -> bool {
        // Same version and KEM algorithm
        self.version == other.version && self.kem_id == other.kem_id
    }

    /// Negotiate parameters between local and peer
    ///
    /// Returns negotiated parameters or None if incompatible
    pub fn negotiate(local: &Self, peer: &Self) -> Option<NegotiatedPcrParams> {
        if !local.is_compatible(peer) {
            return None;
        }

        // Use minimum values for security-sensitive parameters
        Some(NegotiatedPcrParams {
            kem_id: local.kem_id, // Same as peer since compatible
            rekey_interval_secs: local.rekey_interval_secs.min(peer.rekey_interval_secs),
            window: local.window.min(peer.window) as u64,
        })
    }
}

/// Negotiated PCR parameters after handshake
#[derive(Clone, Debug)]
pub struct NegotiatedPcrParams {
    /// Agreed KEM algorithm
    pub kem_id: KemId,
    /// Agreed rekey interval (minimum of both)
    pub rekey_interval_secs: u32,
    /// Agreed window size (minimum of both)
    pub window: u64,
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let param = PcrTransportParam::default();
        let encoded = param.encode();
        let decoded = PcrTransportParam::decode(&encoded).unwrap();
        assert_eq!(param, decoded);
    }

    #[test]
    fn test_encode_decode_custom() {
        let param = PcrTransportParam::new(KemId::X25519, 60, 256);
        let encoded = param.encode();
        let decoded = PcrTransportParam::decode(&encoded).unwrap();
        assert_eq!(param, decoded);
    }

    #[test]
    fn test_decode_too_short() {
        let buf = [0u8; 10];
        assert!(PcrTransportParam::decode(&buf).is_err());
    }

    #[test]
    fn test_decode_invalid_version() {
        let mut param = PcrTransportParam::default();
        param.version = 0xFF;
        let encoded = param.encode();
        // Manually fix the version byte
        let mut bad = encoded.clone();
        bad[0] = 0xFF;
        assert!(PcrTransportParam::decode(&bad).is_err());
    }

    #[test]
    fn test_decode_invalid_kem() {
        let mut buf = PcrTransportParam::default().encode();
        buf[1] = 0xFF;
        buf[2] = 0xFF;
        assert!(PcrTransportParam::decode(&buf).is_err());
    }

    #[test]
    fn test_compatibility() {
        let p1 = PcrTransportParam::default();
        let p2 = PcrTransportParam::default();
        assert!(p1.is_compatible(&p2));

        let p3 = PcrTransportParam::new(KemId::X25519, 60, 256);
        assert!(!p1.is_compatible(&p3)); // Different KEM
    }

    #[test]
    fn test_negotiate() {
        let local = PcrTransportParam::new(KemId::X25519MlKem768, 120, 512);
        let peer = PcrTransportParam::new(KemId::X25519MlKem768, 60, 256);

        let negotiated = PcrTransportParam::negotiate(&local, &peer).unwrap();
        assert_eq!(negotiated.kem_id, KemId::X25519MlKem768);
        assert_eq!(negotiated.rekey_interval_secs, 60); // min
        assert_eq!(negotiated.window, 256); // min
    }

    #[test]
    fn test_negotiate_incompatible() {
        let local = PcrTransportParam::new(KemId::X25519MlKem768, 120, 512);
        let peer = PcrTransportParam::new(KemId::X25519, 120, 512);

        assert!(PcrTransportParam::negotiate(&local, &peer).is_none());
    }

    #[test]
    fn test_kem_sizes() {
        assert_eq!(KemId::X25519.ciphertext_len(), 32);
        assert_eq!(KemId::X25519MlKem768.ciphertext_len(), 32 + 1088);

        assert_eq!(KemId::X25519.public_key_len(), 32);
        assert_eq!(KemId::X25519MlKem768.public_key_len(), 32 + 1184);
    }
}
