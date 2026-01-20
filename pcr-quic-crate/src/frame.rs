//! PCR-QUIC Frame Definitions
//!
//! Defines the PCR_REKEY frame for epoch rekeying operations.
//!
//! # PCR_REKEY Frame
//!
//! ```text
//! PCR_REKEY Frame {
//!     Type (i) = 0xff000002,
//!     Epoch ID (i),
//!     KEM Ciphertext Length (i),
//!     KEM Ciphertext (..),
//! }
//! ```

use crate::{PcrError, Result};
use octets::{Octets, OctetsMut};

use crate::keys::Epoch;
use crate::params::KemId;

/// PCR_REKEY frame type (private-use range)
pub const PCR_REKEY_FRAME_TYPE: u64 = 0xff000002;

/// PCR_REKEY frame for epoch rekeying
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrRekeyFrame {
    /// New epoch ID
    pub epoch_id: Epoch,
    /// KEM ciphertext (encapsulated shared secret)
    pub kem_ciphertext: Vec<u8>,
}

impl PcrRekeyFrame {
    /// Create a new PCR_REKEY frame
    pub fn new(epoch_id: Epoch, kem_ciphertext: Vec<u8>) -> Self {
        Self {
            epoch_id,
            kem_ciphertext,
        }
    }

    /// Calculate the wire length of this frame
    pub fn wire_len(&self) -> usize {
        // Type (varint) + Epoch ID (varint) + CT Length (varint) + CT
        octets::varint_len(PCR_REKEY_FRAME_TYPE)
            + octets::varint_len(self.epoch_id)
            + octets::varint_len(self.kem_ciphertext.len() as u64)
            + self.kem_ciphertext.len()
    }

    /// Encode the frame to bytes
    pub fn to_bytes(&self, out: &mut OctetsMut) -> Result<usize> {
        let start_len = out.cap();

        out.put_varint(PCR_REKEY_FRAME_TYPE).map_err(|_| PcrError::BufferTooShort)?;
        out.put_varint(self.epoch_id).map_err(|_| PcrError::BufferTooShort)?;
        out.put_varint(self.kem_ciphertext.len() as u64).map_err(|_| PcrError::BufferTooShort)?;
        out.put_bytes(&self.kem_ciphertext).map_err(|_| PcrError::BufferTooShort)?;

        Ok(start_len - out.cap())
    }

    /// Decode a frame from bytes (assumes frame type already consumed)
    pub fn from_bytes(b: &mut Octets) -> Result<Self> {
        let epoch_id = b.get_varint().map_err(|_| PcrError::BufferTooShort)?;
        let ct_len = b.get_varint().map_err(|_| PcrError::BufferTooShort)? as usize;

        // Sanity check ciphertext length (max hybrid KEM ct is ~1200 bytes)
        if ct_len > 2048 {
            return Err(PcrError::InvalidFrame);
        }

        let kem_ciphertext = b.get_bytes(ct_len).map_err(|_| PcrError::BufferTooShort)?.to_vec();

        Ok(Self {
            epoch_id,
            kem_ciphertext,
        })
    }

    /// Validate ciphertext length against expected KEM
    pub fn validate_for_kem(&self, kem_id: KemId) -> Result<()> {
        if self.kem_ciphertext.len() != kem_id.ciphertext_len() {
            return Err(PcrError::InvalidFrame);
        }
        Ok(())
    }
}

/// PCR_REKEY_ACK frame for acknowledging epoch transitions
///
/// This is optional but helps the sender know when to retire old epoch keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrRekeyAckFrame {
    /// Acknowledged epoch ID
    pub epoch_id: Epoch,
}

/// PCR_REKEY_ACK frame type
pub const PCR_REKEY_ACK_FRAME_TYPE: u64 = 0xff000003;

impl PcrRekeyAckFrame {
    /// Create a new PCR_REKEY_ACK frame
    pub fn new(epoch_id: Epoch) -> Self {
        Self { epoch_id }
    }

    /// Calculate the wire length of this frame
    pub fn wire_len(&self) -> usize {
        octets::varint_len(PCR_REKEY_ACK_FRAME_TYPE)
            + octets::varint_len(self.epoch_id)
    }

    /// Encode the frame to bytes
    pub fn to_bytes(&self, out: &mut OctetsMut) -> Result<usize> {
        let start_len = out.cap();

        out.put_varint(PCR_REKEY_ACK_FRAME_TYPE).map_err(|_| PcrError::BufferTooShort)?;
        out.put_varint(self.epoch_id).map_err(|_| PcrError::BufferTooShort)?;

        Ok(start_len - out.cap())
    }

    /// Decode a frame from bytes (assumes frame type already consumed)
    pub fn from_bytes(b: &mut Octets) -> Result<Self> {
        let epoch_id = b.get_varint().map_err(|_| PcrError::BufferTooShort)?;
        Ok(Self { epoch_id })
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_pcr_rekey_encode_decode() {
        let frame = PcrRekeyFrame::new(5, vec![0x01, 0x02, 0x03, 0x04]);

        let mut buf = [0u8; 256];
        let mut out = OctetsMut::with_slice(&mut buf);
        let len = frame.to_bytes(&mut out).unwrap();

        let mut input = Octets::with_slice(&buf[..len]);
        
        // Consume frame type
        let frame_type = input.get_varint().unwrap();
        assert_eq!(frame_type, PCR_REKEY_FRAME_TYPE);

        let decoded = PcrRekeyFrame::from_bytes(&mut input).unwrap();
        assert_eq!(decoded.epoch_id, 5);
        assert_eq!(decoded.kem_ciphertext, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_pcr_rekey_wire_len() {
        let frame = PcrRekeyFrame::new(1, vec![0u8; 32]); // X25519-only ct
        let wire_len = frame.wire_len();

        let mut buf = vec![0u8; wire_len];
        let mut out = OctetsMut::with_slice(&mut buf);
        let encoded_len = frame.to_bytes(&mut out).unwrap();

        assert_eq!(wire_len, encoded_len);
    }

    #[test]
    fn test_pcr_rekey_hybrid_ct() {
        // Hybrid KEM ciphertext: 32 (X25519) + 1088 (ML-KEM-768)
        let ct = vec![0xABu8; 1120];
        let frame = PcrRekeyFrame::new(2, ct.clone());

        let mut buf = vec![0u8; frame.wire_len()];
        let mut out = OctetsMut::with_slice(&mut buf);
        frame.to_bytes(&mut out).unwrap();

        let mut input = Octets::with_slice(&buf);
        let _ = input.get_varint().unwrap(); // frame type
        let decoded = PcrRekeyFrame::from_bytes(&mut input).unwrap();

        assert_eq!(decoded.epoch_id, 2);
        assert_eq!(decoded.kem_ciphertext.len(), 1120);
    }

    #[test]
    fn test_pcr_rekey_validate_kem() {
        let frame_x25519 = PcrRekeyFrame::new(1, vec![0u8; 32]);
        assert!(frame_x25519.validate_for_kem(KemId::X25519).is_ok());
        assert!(frame_x25519.validate_for_kem(KemId::X25519MlKem768).is_err());

        let frame_hybrid = PcrRekeyFrame::new(1, vec![0u8; 1120]);
        assert!(frame_hybrid.validate_for_kem(KemId::X25519MlKem768).is_ok());
        assert!(frame_hybrid.validate_for_kem(KemId::X25519).is_err());
    }

    #[test]
    fn test_pcr_rekey_ack_encode_decode() {
        let frame = PcrRekeyAckFrame::new(10);

        let mut buf = [0u8; 32];
        let mut out = OctetsMut::with_slice(&mut buf);
        let len = frame.to_bytes(&mut out).unwrap();

        let mut input = Octets::with_slice(&buf[..len]);
        let frame_type = input.get_varint().unwrap();
        assert_eq!(frame_type, PCR_REKEY_ACK_FRAME_TYPE);

        let decoded = PcrRekeyAckFrame::from_bytes(&mut input).unwrap();
        assert_eq!(decoded.epoch_id, 10);
    }

    #[test]
    fn test_pcr_rekey_invalid_ct_len() {
        // Create oversized ciphertext
        let mut buf = [0u8; 32];
        let mut out = OctetsMut::with_slice(&mut buf);
        out.put_varint(1).unwrap(); // epoch
        out.put_varint(3000).unwrap(); // ct_len > 2048

        let mut input = Octets::with_slice(&buf);
        assert!(PcrRekeyFrame::from_bytes(&mut input).is_err());
    }
}
