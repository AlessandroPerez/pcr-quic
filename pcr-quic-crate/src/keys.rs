//! PCR-QUIC Epoch Key Schedule
//!
//! This module implements the epoch key derivation for PCR-QUIC.
//! Each epoch `e` has a shared secret `ss_e` from the hybrid KEM, from which
//! we derive:
//!
//! - `PRK_epoch`: Used to derive AES encryption keys
//! - `PRK_chain`: Used to derive IV bases for per-packet nonce ratchet
//! - `K_server`, `K_client`: AES-256 keys for each direction
//! - `IV_server`, `IV_client`: IV bases for nonce derivation
//!
//! # Key Derivation
//!
//! ```text
//! ss_e (from KEM)
//!   |
//!   +---> PRK_epoch = HKDF(0x36 || ss, salt=epoch, info="pcr-epoch")
//!   |       |
//!   |       +---> K_server = HKDF(PRK_epoch, info="server aes key chain")
//!   |       +---> K_client = HKDF(PRK_epoch, info="client aes key chain")
//!   |
//!   +---> PRK_chain = HKDF(0x5C || ss, salt=epoch, info="pcr-chain")
//!           |
//!           +---> IV_server = HKDF(PRK_chain, info="server iv key chain")
//!           +---> IV_client = HKDF(PRK_chain, info="client iv key chain")
//! ```

use crate::pcr_shim::{self, SecretBytes};
use crate::Result;

/// Epoch identifier (monotonically increasing)
pub type Epoch = u64;

/// Direction of packet flow
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Client sending to server
    ClientToServer,
    /// Server sending to client
    ServerToClient,
}

impl Direction {
    /// Returns the opposite direction
    pub fn opposite(self) -> Self {
        match self {
            Direction::ClientToServer => Direction::ServerToClient,
            Direction::ServerToClient => Direction::ClientToServer,
        }
    }
}

/// Keys derived for a single epoch
///
/// Contains all cryptographic material needed for packet protection
/// within an epoch. Should be securely zeroized when the epoch is retired.
#[derive(Clone)]
pub struct EpochKeys {
    /// The epoch number these keys belong to
    pub epoch: Epoch,
    
    /// AES-256 key for sending packets
    pub k_send: SecretBytes<32>,
    
    /// AES-256 key for receiving packets
    pub k_recv: SecretBytes<32>,
    
    /// IV base for sending (used with per-packet nonce ratchet)
    /// Only first 12 bytes are used as the IV
    pub iv_send: SecretBytes<32>,
    
    /// IV base for receiving (used with per-packet nonce ratchet)
    /// Only first 12 bytes are used as the IV
    pub iv_recv: SecretBytes<32>,
    
    /// PRK for epoch key derivation (kept for potential rekeying)
    pub prk_epoch: SecretBytes<32>,
    
    /// PRK for chain/IV derivation (used by per-packet ratchet)
    pub prk_chain: SecretBytes<32>,
}

impl EpochKeys {
    /// Get the 12-byte IV for sending
    pub fn iv_send_12(&self) -> &[u8; 12] {
        self.iv_send.as_bytes()[..12].try_into().unwrap()
    }
    
    /// Get the 12-byte IV for receiving
    pub fn iv_recv_12(&self) -> &[u8; 12] {
        self.iv_recv.as_bytes()[..12].try_into().unwrap()
    }
}

/// HKDF prefix byte for epoch PRK derivation (HMAC outer pad XOR pattern)
const PRK_EPOCH_PREFIX: u8 = 0x36;

/// HKDF prefix byte for chain PRK derivation (HMAC inner pad XOR pattern)
const PRK_CHAIN_PREFIX: u8 = 0x5C;

/// Info string for epoch PRK derivation
const INFO_PCR_EPOCH: &[u8] = b"pcr-epoch";

/// Info string for chain PRK derivation
const INFO_PCR_CHAIN: &[u8] = b"pcr-chain";

/// Info string for server AES key derivation
const INFO_SERVER_AES_KEY: &[u8] = b"server aes key chain";

/// Info string for client AES key derivation
const INFO_CLIENT_AES_KEY: &[u8] = b"client aes key chain";

/// Info string for server IV derivation
const INFO_SERVER_IV: &[u8] = b"server iv key chain";

/// Info string for client IV derivation
const INFO_CLIENT_IV: &[u8] = b"client iv key chain";

/// Derive PRK_epoch and PRK_chain from a shared secret
///
/// # Arguments
/// * `ss` - 32-byte shared secret from KEM
/// * `epoch` - Current epoch number (used as salt)
///
/// # Returns
/// Tuple of (PRK_epoch, PRK_chain), each 32 bytes
///
/// # Security
/// The shared secret `ss` should be zeroized immediately after this call.
pub fn derive_prks(ss: &[u8; 32], epoch: Epoch) -> Result<(SecretBytes<32>, SecretBytes<32>)> {
    // Build IKM for PRK_epoch: 0x36 || ss
    let mut ikm_epoch = Vec::with_capacity(1 + ss.len());
    ikm_epoch.push(PRK_EPOCH_PREFIX);
    ikm_epoch.extend_from_slice(ss);

    // Build IKM for PRK_chain: 0x5C || ss
    let mut ikm_chain = Vec::with_capacity(1 + ss.len());
    ikm_chain.push(PRK_CHAIN_PREFIX);
    ikm_chain.extend_from_slice(ss);

    // Use epoch as salt (big-endian)
    let salt = epoch.to_be_bytes();

    // Derive PRKs
    let prk_epoch_vec = pcr_shim::hkdf_sha256(&ikm_epoch, &salt, INFO_PCR_EPOCH, 32)?;
    let prk_chain_vec = pcr_shim::hkdf_sha256(&ikm_chain, &salt, INFO_PCR_CHAIN, 32)?;

    // Convert to fixed-size arrays with secure storage
    let mut prk_epoch = SecretBytes::<32>::new();
    prk_epoch.as_bytes_mut().copy_from_slice(&prk_epoch_vec);

    let mut prk_chain = SecretBytes::<32>::new();
    prk_chain.as_bytes_mut().copy_from_slice(&prk_chain_vec);

    // Zeroize temporary vectors
    let mut ikm_epoch = ikm_epoch;
    let mut ikm_chain = ikm_chain;
    pcr_shim::secure_zero(&mut ikm_epoch);
    pcr_shim::secure_zero(&mut ikm_chain);

    Ok((prk_epoch, prk_chain))
}

/// Derive all epoch keys from a shared secret
///
/// # Arguments
/// * `ss` - 32-byte shared secret from KEM (will NOT be zeroized - caller must do this)
/// * `epoch` - Current epoch number
/// * `is_client` - True if we are the client, false if server
///
/// # Returns
/// `EpochKeys` containing all derived keys for this epoch
///
/// # Security
/// - The shared secret `ss` should be zeroized by the caller after this returns
/// - The returned `EpochKeys` should be zeroized when the epoch is retired
pub fn derive_epoch_keys(ss: &[u8; 32], epoch: Epoch, is_client: bool) -> Result<EpochKeys> {
    // Derive PRKs from shared secret
    let (prk_epoch, prk_chain) = derive_prks(ss, epoch)?;

    // Derive AES keys from PRK_epoch
    let k_server_vec = pcr_shim::hkdf_sha256(
        prk_epoch.as_bytes(),
        &[],
        INFO_SERVER_AES_KEY,
        32,
    )?;
    let k_client_vec = pcr_shim::hkdf_sha256(
        prk_epoch.as_bytes(),
        &[],
        INFO_CLIENT_AES_KEY,
        32,
    )?;

    // Derive IVs from PRK_chain
    let iv_server_vec = pcr_shim::hkdf_sha256(
        prk_chain.as_bytes(),
        &[],
        INFO_SERVER_IV,
        32,
    )?;
    let iv_client_vec = pcr_shim::hkdf_sha256(
        prk_chain.as_bytes(),
        &[],
        INFO_CLIENT_IV,
        32,
    )?;

    // Convert to SecretBytes
    let mut k_server = SecretBytes::<32>::new();
    k_server.as_bytes_mut().copy_from_slice(&k_server_vec);

    let mut k_client = SecretBytes::<32>::new();
    k_client.as_bytes_mut().copy_from_slice(&k_client_vec);

    let mut iv_server = SecretBytes::<32>::new();
    iv_server.as_bytes_mut().copy_from_slice(&iv_server_vec);

    let mut iv_client = SecretBytes::<32>::new();
    iv_client.as_bytes_mut().copy_from_slice(&iv_client_vec);

    // Assign send/recv based on role
    let (k_send, k_recv, iv_send, iv_recv) = if is_client {
        (k_client, k_server, iv_client, iv_server)
    } else {
        (k_server, k_client, iv_server, iv_client)
    };

    Ok(EpochKeys {
        epoch,
        k_send,
        k_recv,
        iv_send,
        iv_recv,
        prk_epoch,
        prk_chain,
    })
}

/// Derive epoch keys for a specific direction only
///
/// This is useful when you only need keys for one direction (e.g., during
/// initial handshake when only one party is sending).
///
/// # Arguments
/// * `ss` - 32-byte shared secret from KEM
/// * `epoch` - Current epoch number
/// * `direction` - Which direction to derive keys for
///
/// # Returns
/// Tuple of (AES key, IV base) for the specified direction
pub fn derive_direction_keys(
    ss: &[u8; 32],
    epoch: Epoch,
    direction: Direction,
) -> Result<(SecretBytes<32>, SecretBytes<32>)> {
    let (prk_epoch, prk_chain) = derive_prks(ss, epoch)?;

    let (key_info, iv_info) = match direction {
        Direction::ClientToServer => (INFO_CLIENT_AES_KEY, INFO_CLIENT_IV),
        Direction::ServerToClient => (INFO_SERVER_AES_KEY, INFO_SERVER_IV),
    };

    let key_vec = pcr_shim::hkdf_sha256(prk_epoch.as_bytes(), &[], key_info, 32)?;
    let iv_vec = pcr_shim::hkdf_sha256(prk_chain.as_bytes(), &[], iv_info, 32)?;

    let mut key = SecretBytes::<32>::new();
    key.as_bytes_mut().copy_from_slice(&key_vec);

    let mut iv = SecretBytes::<32>::new();
    iv.as_bytes_mut().copy_from_slice(&iv_vec);

    Ok((key, iv))
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_derive_prks() {
        let ss = [0x42u8; 32];
        let epoch = 1;

        let (prk_epoch, prk_chain) = derive_prks(&ss, epoch).unwrap();

        // PRKs should be different
        assert_ne!(prk_epoch.as_bytes(), prk_chain.as_bytes());

        // PRKs should be deterministic
        let (prk_epoch2, prk_chain2) = derive_prks(&ss, epoch).unwrap();
        assert_eq!(prk_epoch.as_bytes(), prk_epoch2.as_bytes());
        assert_eq!(prk_chain.as_bytes(), prk_chain2.as_bytes());

        // Different epoch should give different PRKs
        let (prk_epoch3, prk_chain3) = derive_prks(&ss, epoch + 1).unwrap();
        assert_ne!(prk_epoch.as_bytes(), prk_epoch3.as_bytes());
        assert_ne!(prk_chain.as_bytes(), prk_chain3.as_bytes());
    }

    #[test]
    fn test_derive_epoch_keys_client_server_symmetry() {
        let ss = [0x42u8; 32];
        let epoch = 1;

        let client_keys = derive_epoch_keys(&ss, epoch, true).unwrap();
        let server_keys = derive_epoch_keys(&ss, epoch, false).unwrap();

        // Client's send key should be server's recv key
        assert_eq!(client_keys.k_send.as_bytes(), server_keys.k_recv.as_bytes());
        assert_eq!(client_keys.k_recv.as_bytes(), server_keys.k_send.as_bytes());

        // Same for IVs
        assert_eq!(client_keys.iv_send.as_bytes(), server_keys.iv_recv.as_bytes());
        assert_eq!(client_keys.iv_recv.as_bytes(), server_keys.iv_send.as_bytes());

        // PRKs should be the same
        assert_eq!(client_keys.prk_epoch.as_bytes(), server_keys.prk_epoch.as_bytes());
        assert_eq!(client_keys.prk_chain.as_bytes(), server_keys.prk_chain.as_bytes());
    }

    #[test]
    fn test_derive_epoch_keys_deterministic() {
        let ss = [0x42u8; 32];
        let epoch = 5;

        let keys1 = derive_epoch_keys(&ss, epoch, true).unwrap();
        let keys2 = derive_epoch_keys(&ss, epoch, true).unwrap();

        assert_eq!(keys1.k_send.as_bytes(), keys2.k_send.as_bytes());
        assert_eq!(keys1.k_recv.as_bytes(), keys2.k_recv.as_bytes());
        assert_eq!(keys1.iv_send.as_bytes(), keys2.iv_send.as_bytes());
        assert_eq!(keys1.iv_recv.as_bytes(), keys2.iv_recv.as_bytes());
    }

    #[test]
    fn test_derive_epoch_keys_different_epochs() {
        let ss = [0x42u8; 32];

        let keys1 = derive_epoch_keys(&ss, 1, true).unwrap();
        let keys2 = derive_epoch_keys(&ss, 2, true).unwrap();

        // Different epochs should produce different keys
        assert_ne!(keys1.k_send.as_bytes(), keys2.k_send.as_bytes());
        assert_ne!(keys1.k_recv.as_bytes(), keys2.k_recv.as_bytes());
        assert_ne!(keys1.iv_send.as_bytes(), keys2.iv_send.as_bytes());
        assert_ne!(keys1.iv_recv.as_bytes(), keys2.iv_recv.as_bytes());
    }

    #[test]
    fn test_derive_direction_keys() {
        let ss = [0x42u8; 32];
        let epoch = 1;

        let (c2s_key, c2s_iv) = derive_direction_keys(&ss, epoch, Direction::ClientToServer).unwrap();
        let (s2c_key, s2c_iv) = derive_direction_keys(&ss, epoch, Direction::ServerToClient).unwrap();

        // Different directions should have different keys
        assert_ne!(c2s_key.as_bytes(), s2c_key.as_bytes());
        assert_ne!(c2s_iv.as_bytes(), s2c_iv.as_bytes());

        // Should match the full epoch key derivation
        let client_keys = derive_epoch_keys(&ss, epoch, true).unwrap();
        assert_eq!(c2s_key.as_bytes(), client_keys.k_send.as_bytes());
        assert_eq!(c2s_iv.as_bytes(), client_keys.iv_send.as_bytes());
        assert_eq!(s2c_key.as_bytes(), client_keys.k_recv.as_bytes());
        assert_eq!(s2c_iv.as_bytes(), client_keys.iv_recv.as_bytes());
    }

    #[test]
    fn test_direction_opposite() {
        assert_eq!(Direction::ClientToServer.opposite(), Direction::ServerToClient);
        assert_eq!(Direction::ServerToClient.opposite(), Direction::ClientToServer);
    }

    #[test]
    fn test_iv_12_byte_accessor() {
        let ss = [0x42u8; 32];
        let keys = derive_epoch_keys(&ss, 1, true).unwrap();

        let iv_send_12 = keys.iv_send_12();
        let iv_recv_12 = keys.iv_recv_12();

        assert_eq!(iv_send_12.len(), 12);
        assert_eq!(iv_recv_12.len(), 12);
        assert_eq!(iv_send_12, &keys.iv_send.as_bytes()[..12]);
        assert_eq!(iv_recv_12, &keys.iv_recv.as_bytes()[..12]);
    }
}
