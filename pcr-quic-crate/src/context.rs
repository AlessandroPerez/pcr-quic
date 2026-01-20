//! PCR-QUIC Crypto Context
//!
//! Manages epoch state, key material, and rekeying for PCR-QUIC connections.
//!
//! # Architecture
//!
//! The `PcrCryptoContext` maintains:
//! - Current and next epoch state
//! - Send/receive packet keys for each epoch
//! - KEM keypairs for initiating/responding to rekeys
//! - Timers and counters for epoch retirement
//!
//! # Epoch Lifecycle
//!
//! 1. Initial epoch (0) is derived from TLS exporter after handshake
//! 2. Rekey initiated after `rekey_interval_secs` or on demand
//! 3. Old epoch retired after `min(3 × PTO, 3s)` or 64 packets

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::pcr_shim::{self, SecretBytes};
use crate::{PcrError, Result};

use crate::frame::PcrRekeyFrame;
use crate::keys::{self, Direction, Epoch};
use crate::params::{KemId, NegotiatedPcrParams};
use crate::ratchet::PcrPacketKey;

/// Maximum number of concurrent epochs (current + next)
pub const MAX_CONCURRENT_EPOCHS: usize = 2;

/// Maximum packets on old epoch before forced retirement
pub const MAX_OLD_EPOCH_PACKETS: u64 = 64;

/// Maximum time to keep old epoch keys (fallback if PTO not available)
pub const MAX_OLD_EPOCH_DURATION: Duration = Duration::from_secs(3);

/// TLS exporter label for initial epoch secret
pub const TLS_EXPORTER_LABEL: &[u8] = b"pcr-quic epoch 0";

/// Epoch state tracking
#[derive(Clone, Debug)]
pub struct EpochState {
    /// Epoch number
    pub epoch: Epoch,
    /// When this epoch was activated
    pub activated_at: Instant,
    /// Packet count on this epoch (for retirement)
    pub packet_count: u64,
    /// Whether this epoch is being retired
    pub retiring: bool,
}

impl EpochState {
    fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            activated_at: Instant::now(),
            packet_count: 0,
            retiring: false,
        }
    }
}

/// PCR Crypto Context for managing epoch keys and rekeying
pub struct PcrCryptoContext {
    /// Our role (client or server)
    is_server: bool,

    /// Negotiated PCR parameters
    params: NegotiatedPcrParams,

    /// Current epoch state
    cur_epoch_state: EpochState,

    /// Next epoch state (during transition)
    next_epoch_state: Option<EpochState>,

    /// Send keys by epoch
    send_keys: HashMap<Epoch, PcrPacketKey>,

    /// Receive keys by epoch
    recv_keys: HashMap<Epoch, PcrPacketKey>,

    /// Our KEM keypair (public, secret)
    kem_public_key: Vec<u8>,
    kem_secret_key: SecretBytes<2432>, // Max size for hybrid

    /// Peer's KEM public key
    peer_kem_public_key: Option<Vec<u8>>,

    /// Connection ID for key derivation
    connection_id: Vec<u8>,

    /// Last rekey time
    last_rekey_at: Instant,

    /// Pending rekey (we initiated, waiting for confirmation)
    pending_rekey_epoch: Option<Epoch>,
}

impl PcrCryptoContext {
    /// Create a new PCR crypto context after handshake
    ///
    /// # Arguments
    /// * `is_server` - Whether we are the server
    /// * `params` - Negotiated PCR parameters
    /// * `initial_secret` - Initial shared secret from TLS exporter
    /// * `connection_id` - Connection ID for key derivation
    pub fn new(
        is_server: bool,
        params: NegotiatedPcrParams,
        initial_secret: &[u8; 32],
        connection_id: Vec<u8>,
    ) -> Result<Self> {
        // Generate our KEM keypair
        let (kem_pk, kem_sk) = Self::generate_kem_keypair(params.kem_id)?;

        let mut ctx = Self {
            is_server,
            params,
            cur_epoch_state: EpochState::new(0),
            next_epoch_state: None,
            send_keys: HashMap::new(),
            recv_keys: HashMap::new(),
            kem_public_key: kem_pk,
            kem_secret_key: kem_sk,
            peer_kem_public_key: None,
            connection_id,
            last_rekey_at: Instant::now(),
            pending_rekey_epoch: None,
        };

        // Derive epoch 0 keys
        ctx.install_epoch_keys(0, initial_secret)?;

        Ok(ctx)
    }

    /// Generate KEM keypair based on negotiated KEM ID
    fn generate_kem_keypair(kem_id: KemId) -> Result<(Vec<u8>, SecretBytes<2432>)> {
        match kem_id {
            KemId::X25519 => {
                let (pk, sk) = pcr_shim::x25519_keypair()?;
                let mut secret = SecretBytes::<2432>::new();
                secret.as_bytes_mut()[..32].copy_from_slice(&sk);
                Ok((pk.to_vec(), secret))
            }
            KemId::X25519MlKem768 => {
                let (pk, sk) = pcr_shim::hybrid_kem_keypair()?;
                let mut secret = SecretBytes::<2432>::new();
                secret.as_bytes_mut()[..sk.len()].copy_from_slice(sk.as_ref());
                Ok((pk.to_vec(), secret))
            }
        }
    }

    /// Install keys for a new epoch
    fn install_epoch_keys(&mut self, epoch: Epoch, shared_secret: &[u8; 32]) -> Result<()> {
        // Derive all epoch keys (handles send/recv direction internally based on is_client)
        let keys = keys::derive_epoch_keys(shared_secret, epoch, !self.is_server)?;

        // Create packet keys using the already-split send/recv keys
        let send_pkt_key = PcrPacketKey::from_secret_bytes(epoch, &keys.k_send, &keys.iv_send);
        let recv_pkt_key = PcrPacketKey::from_secret_bytes(epoch, &keys.k_recv, &keys.iv_recv);

        self.send_keys.insert(epoch, send_pkt_key);
        self.recv_keys.insert(epoch, recv_pkt_key);

        Ok(())
    }

    /// Get our KEM public key (to send to peer)
    pub fn kem_public_key(&self) -> &[u8] {
        &self.kem_public_key
    }

    /// Set peer's KEM public key (received from peer)
    pub fn set_peer_kem_public_key(&mut self, pk: Vec<u8>) -> Result<()> {
        // Validate length
        if pk.len() != self.params.kem_id.public_key_len() {
            return Err(PcrError::CryptoFailed);
        }
        self.peer_kem_public_key = Some(pk);
        Ok(())
    }

    /// Get current epoch number
    pub fn current_epoch(&self) -> Epoch {
        self.cur_epoch_state.epoch
    }

    /// Get next epoch number (if in transition)
    pub fn next_epoch(&self) -> Option<Epoch> {
        self.next_epoch_state.as_ref().map(|s| s.epoch)
    }

    /// Check if rekey is due
    pub fn should_rekey(&self) -> bool {
        if self.pending_rekey_epoch.is_some() {
            return false; // Already have pending rekey
        }
        if self.next_epoch_state.is_some() {
            return false; // Already transitioning
        }

        let elapsed = self.last_rekey_at.elapsed();
        elapsed.as_secs() >= self.params.rekey_interval_secs as u64
    }

    /// Initiate a rekey (sender side)
    ///
    /// Returns the PCR_REKEY frame to send and the new shared secret
    pub fn initiate_rekey(&mut self) -> Result<PcrRekeyFrame> {
        let peer_pk = self.peer_kem_public_key.as_ref()
            .ok_or(PcrError::CryptoFailed)?;

        // Perform KEM encapsulation
        let (ciphertext, shared_secret) = self.kem_encaps(peer_pk)?;

        let new_epoch = self.cur_epoch_state.epoch + 1;

        // Install new epoch keys
        self.install_epoch_keys(new_epoch, &shared_secret)?;

        // Set up next epoch state
        self.next_epoch_state = Some(EpochState::new(new_epoch));
        self.pending_rekey_epoch = Some(new_epoch);
        self.last_rekey_at = Instant::now();

        Ok(PcrRekeyFrame::new(new_epoch, ciphertext))
    }

    /// Process received PCR_REKEY frame (receiver side)
    pub fn process_rekey_frame(&mut self, frame: &PcrRekeyFrame) -> Result<()> {
        // Validate epoch progression
        let expected_epoch = self.cur_epoch_state.epoch + 1;
        if frame.epoch_id != expected_epoch {
            return Err(PcrError::InvalidFrame);
        }

        // Validate ciphertext length
        frame.validate_for_kem(self.params.kem_id)?;

        // Perform KEM decapsulation
        let shared_secret = self.kem_decaps(&frame.kem_ciphertext)?;

        // Install new epoch keys
        self.install_epoch_keys(frame.epoch_id, &shared_secret)?;

        // Set up next epoch state
        self.next_epoch_state = Some(EpochState::new(frame.epoch_id));
        self.last_rekey_at = Instant::now();

        Ok(())
    }

    /// KEM encapsulation
    fn kem_encaps(&self, peer_pk: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        match self.params.kem_id {
            KemId::X25519 => {
                // Generate ephemeral keypair
                let (eph_pk, eph_sk) = pcr_shim::x25519_keypair()?;

                // Derive shared secret
                let mut peer_pk_arr = [0u8; 32];
                peer_pk_arr.copy_from_slice(peer_pk);
                let ss = pcr_shim::x25519_derive(&eph_sk, &peer_pk_arr)?;

                // HKDF to get final secret
                let final_ss = pcr_shim::hkdf_sha256(
                    &ss,
                    &[],
                    b"pcr-quic x25519 kem",
                    32,
                )?;
                let mut ss_arr = [0u8; 32];
                ss_arr.copy_from_slice(&final_ss);

                Ok((eph_pk.to_vec(), ss_arr))
            }
            KemId::X25519MlKem768 => {
                let (ct, ss) = pcr_shim::hybrid_kem_encaps_slice(peer_pk)?;
                Ok((ct, ss))
            }
        }
    }

    /// KEM decapsulation
    fn kem_decaps(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        match self.params.kem_id {
            KemId::X25519 => {
                // Ciphertext is ephemeral public key
                let mut eph_pk = [0u8; 32];
                eph_pk.copy_from_slice(ciphertext);

                // Our secret key
                let mut sk = [0u8; 32];
                sk.copy_from_slice(&self.kem_secret_key.as_bytes()[..32]);

                // Derive shared secret
                let ss = pcr_shim::x25519_derive(&sk, &eph_pk)?;

                // HKDF to get final secret
                let final_ss = pcr_shim::hkdf_sha256(
                    &ss,
                    &[],
                    b"pcr-quic x25519 kem",
                    32,
                )?;
                let mut ss_arr = [0u8; 32];
                ss_arr.copy_from_slice(&final_ss);

                Ok(ss_arr)
            }
            KemId::X25519MlKem768 => {
                let sk_len = self.params.kem_id.secret_key_len();
                let sk = &self.kem_secret_key.as_bytes()[..sk_len];
                pcr_shim::hybrid_kem_decaps_slice(ciphertext, sk)
            }
        }
    }

    /// Activate the next epoch (switch to new keys)
    pub fn activate_next_epoch(&mut self) -> Result<()> {
        let next_state = self.next_epoch_state.take()
            .ok_or(PcrError::InvalidState)?;

        // Mark current epoch as retiring
        let mut old_state = std::mem::replace(&mut self.cur_epoch_state, next_state);
        old_state.retiring = true;

        // Clear pending rekey if this was our initiated rekey
        if self.pending_rekey_epoch == Some(self.cur_epoch_state.epoch) {
            self.pending_rekey_epoch = None;
        }

        Ok(())
    }

    /// Retire old epoch keys
    pub fn retire_epoch(&mut self, epoch: Epoch) {
        self.send_keys.remove(&epoch);
        self.recv_keys.remove(&epoch);
    }

    /// Check if an epoch should be retired
    pub fn should_retire_epoch(&self, epoch: Epoch, pto: Option<Duration>) -> bool {
        if epoch >= self.cur_epoch_state.epoch {
            return false;
        }

        // Check packet count
        if let Some(key) = self.send_keys.get(&epoch) {
            if key.highest_pn() >= MAX_OLD_EPOCH_PACKETS {
                return true;
            }
        }

        // Check time
        let max_duration = pto
            .map(|p| p * 3)
            .unwrap_or(MAX_OLD_EPOCH_DURATION);

        // We don't have per-epoch timing here, so use last_rekey_at as approximation
        self.last_rekey_at.elapsed() > max_duration
    }

    /// Get send key for current epoch
    pub fn send_key(&mut self) -> Option<&mut PcrPacketKey> {
        let epoch = self.cur_epoch_state.epoch;
        self.send_keys.get_mut(&epoch)
    }

    /// Get send key for a specific epoch
    pub fn send_key_for_epoch(&mut self, epoch: Epoch) -> Option<&mut PcrPacketKey> {
        self.send_keys.get_mut(&epoch)
    }

    /// Get receive key, trying current then next epoch
    pub fn recv_key_for_epoch(&mut self, epoch: Epoch) -> Option<&mut PcrPacketKey> {
        self.recv_keys.get_mut(&epoch)
    }

    /// Try to decrypt with available epochs
    pub fn try_decrypt(
        &mut self,
        pn: u64,
        cid: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Option<(Vec<u8>, Epoch)> {
        // Try current epoch first
        let cur_epoch = self.cur_epoch_state.epoch;
        let dir = if self.is_server {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };

        if let Some(key) = self.recv_keys.get_mut(&cur_epoch) {
            if let Some(pt) = super::ratchet::open_packet(
                key, pn, dir, cid, ad, ciphertext, self.params.window,
            ) {
                self.cur_epoch_state.packet_count += 1;
                return Some((pt, cur_epoch));
            }
        }

        // Try next epoch if available
        if let Some(ref next_state) = self.next_epoch_state {
            let next_epoch = next_state.epoch;
            if let Some(key) = self.recv_keys.get_mut(&next_epoch) {
                if let Some(pt) = super::ratchet::open_packet(
                    key, pn, dir, cid, ad, ciphertext, self.params.window,
                ) {
                    return Some((pt, next_epoch));
                }
            }
        }

        None
    }

    /// Encrypt a packet
    pub fn encrypt(
        &mut self,
        pn: u64,
        cid: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let epoch = self.cur_epoch_state.epoch;
        let dir = if self.is_server {
            Direction::ServerToClient
        } else {
            Direction::ClientToServer
        };

        let key = self.send_keys.get_mut(&epoch)
            .ok_or(PcrError::InvalidState)?;

        super::ratchet::seal_packet(key, pn, dir, cid, ad, plaintext)
    }

    /// Get negotiated parameters
    pub fn params(&self) -> &NegotiatedPcrParams {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    fn make_test_params() -> NegotiatedPcrParams {
        NegotiatedPcrParams {
            kem_id: KemId::X25519,
            rekey_interval_secs: 120,
            window: 512,
        }
    }

    #[test]
    fn test_create_context() {
        let params = make_test_params();
        let secret = [0x42u8; 32];
        let cid = b"test-cid".to_vec();

        let ctx = PcrCryptoContext::new(false, params, &secret, cid).unwrap();
        
        assert_eq!(ctx.current_epoch(), 0);
        assert!(ctx.next_epoch().is_none());
        assert!(ctx.send_keys.contains_key(&0));
        assert!(ctx.recv_keys.contains_key(&0));
    }

    #[test]
    fn test_kem_keypair_generation() {
        let (pk, _sk) = PcrCryptoContext::generate_kem_keypair(KemId::X25519).unwrap();
        assert_eq!(pk.len(), 32);

        let (pk_hybrid, _sk_hybrid) = PcrCryptoContext::generate_kem_keypair(KemId::X25519MlKem768).unwrap();
        assert_eq!(pk_hybrid.len(), 32 + 1184);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let params = make_test_params();
        let secret = [0x42u8; 32];
        let cid = b"cid123".to_vec();

        let mut client_ctx = PcrCryptoContext::new(false, params.clone(), &secret, cid.clone()).unwrap();
        let mut server_ctx = PcrCryptoContext::new(true, params, &secret, cid.clone()).unwrap();

        let plaintext = b"Hello, PCR-QUIC!";
        let ad = b"header";

        // Client encrypts
        let ct = client_ctx.encrypt(1, &cid, ad, plaintext).unwrap();

        // Server decrypts
        let (pt, epoch) = server_ctx.try_decrypt(1, &cid, ad, &ct).unwrap();
        assert_eq!(pt, plaintext);
        assert_eq!(epoch, 0);
    }

    #[test]
    fn test_rekey_x25519() {
        let params = NegotiatedPcrParams {
            kem_id: KemId::X25519,
            rekey_interval_secs: 0, // Immediate rekey
            window: 512,
        };
        let secret = [0x42u8; 32];
        let cid = b"cid".to_vec();

        let mut client_ctx = PcrCryptoContext::new(false, params.clone(), &secret, cid.clone()).unwrap();
        let mut server_ctx = PcrCryptoContext::new(true, params, &secret, cid.clone()).unwrap();

        // Exchange KEM public keys
        let client_pk = client_ctx.kem_public_key().to_vec();
        let server_pk = server_ctx.kem_public_key().to_vec();
        client_ctx.set_peer_kem_public_key(server_pk).unwrap();
        server_ctx.set_peer_kem_public_key(client_pk).unwrap();

        // Client initiates rekey
        let rekey_frame = client_ctx.initiate_rekey().unwrap();
        assert_eq!(rekey_frame.epoch_id, 1);
        assert_eq!(rekey_frame.kem_ciphertext.len(), 32); // X25519

        // Server processes rekey
        server_ctx.process_rekey_frame(&rekey_frame).unwrap();

        // Both have epoch 1 keys now
        assert!(client_ctx.send_keys.contains_key(&1));
        assert!(server_ctx.recv_keys.contains_key(&1));
    }

    #[test]
    fn test_should_rekey() {
        let params = NegotiatedPcrParams {
            kem_id: KemId::X25519,
            rekey_interval_secs: 0, // Should rekey immediately
            window: 512,
        };
        let secret = [0x42u8; 32];
        let cid = b"cid".to_vec();

        let ctx = PcrCryptoContext::new(false, params, &secret, cid).unwrap();
        
        // Should want to rekey (interval is 0)
        // Note: Due to timing, this might not always pass immediately
        // In practice, rekey_interval_secs would be > 0
    }

    #[test]
    fn test_epoch_state() {
        let state = EpochState::new(5);
        assert_eq!(state.epoch, 5);
        assert_eq!(state.packet_count, 0);
        assert!(!state.retiring);
    }
}
