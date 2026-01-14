//! Basic example showing how to use pcr-quic for packet encryption
//!
//! This demonstrates:
//! 1. Deriving epoch keys from a shared secret
//! 2. Initializing the per-packet ratchet
//! 3. Sealing (encrypting) packets
//! 4. Opening (decrypting) packets in-order and out-of-order

use pcr_quic::{
    keys::{derive_epoch_keys, Direction},
    ratchet::{seal_packet, open_packet, PcrPacketKey},
    Result,
};

fn main() -> Result<()> {
    println!("PCR-QUIC Basic Ratchet Example\n");
    
    // Step 1: Generate a shared secret (in real usage, this comes from KEM)
    let shared_secret: [u8; 32] = [0x42; 32]; // Example: all bytes set to 0x42
    let epoch: u64 = 1;
    let is_client = true; // We're the client
    
    println!("=== Epoch Key Derivation ===");
    println!("Shared Secret: {:02x?}...", &shared_secret[..8]);
    println!("Epoch: {}", epoch);
    println!("Role: Client\n");
    
    // Step 2: Derive epoch keys
    let epoch_keys = derive_epoch_keys(&shared_secret, epoch, is_client)?;
    println!("✓ Derived epoch keys");
    println!("  - K_send (AES-256): {:02x?}...", &epoch_keys.k_send.as_bytes()[..8]);
    println!("  - IV_send: {:02x?}...", &epoch_keys.iv_send.as_bytes()[..8]);
    println!();
    
    // Step 3: Initialize packet key for sending
    let mut k_send = [0u8; 32];
    k_send.copy_from_slice(epoch_keys.k_send.as_bytes());
    let mut iv_send = [0u8; 32];
    iv_send.copy_from_slice(epoch_keys.iv_send.as_bytes());
    let mut send_key = PcrPacketKey::new(epoch_keys.epoch, k_send, iv_send);
    
    // Step 4: Initialize packet key for receiving (simulate remote peer)
    // The remote peer uses the recv keys (opposite direction)
    let mut k_recv = [0u8; 32];
    k_recv.copy_from_slice(epoch_keys.k_recv.as_bytes());
    let mut iv_recv = [0u8; 32];
    iv_recv.copy_from_slice(epoch_keys.iv_recv.as_bytes());
    let mut recv_key = PcrPacketKey::new(epoch_keys.epoch, k_recv, iv_recv);
    
    println!("=== Packet Sealing (Encryption) ===");
    
    // Connection parameters
    let direction = Direction::ClientToServer; // Client sending to server
    let connection_id = b"test-connection-id";
    let additional_data = b"quic-header"; // QUIC packet header
    
    // Seal 5 packets in sequence
    let mut sealed_packets = Vec::new();
    for pn in 0..5 {
        let plaintext = format!("Hello from packet {}", pn);
        let ciphertext = seal_packet(
            &mut send_key,
            pn,
            direction,
            connection_id,
            additional_data,
            plaintext.as_bytes(),
        )?;
        
        println!("Packet {} sealed: {} bytes plaintext -> {} bytes ciphertext",
                 pn, plaintext.len(), ciphertext.len());
        sealed_packets.push((pn, ciphertext));
    }
    println!();
    
    println!("=== Packet Opening (Decryption) ===");
    
    // Open packets in order (simulates ideal network)
    println!("Opening in-order:");
    for (pn, ciphertext) in sealed_packets.iter().take(3) {
        let plaintext = open_packet(
            &mut recv_key,
            *pn,
            direction,
            connection_id,
            additional_data,
            ciphertext,
            512, // Skip window size
        ).expect(&format!("Failed to open packet {}", pn));
        
        let msg = String::from_utf8_lossy(&plaintext);
        println!("  Packet {}: \"{}\" (✓ authenticated)", pn, msg);
    }
    println!();
    
    // Simulate out-of-order delivery: packet 4 arrives before packet 3
    println!("Opening out-of-order (packet 4 before packet 3):");
    let (pn4, ciphertext4) = &sealed_packets[4];
    let plaintext4 = open_packet(
        &mut recv_key,
        *pn4,
        direction,
        connection_id,
        additional_data,
        ciphertext4,
        512,
    ).expect(&format!("Failed to open packet {}", pn4));
    println!("  Packet {}: \"{}\" (✓ authenticated, cached nonce key)", 
             pn4, String::from_utf8_lossy(&plaintext4));
    
    // Now receive the missing packet 3
    let (pn3, ciphertext3) = &sealed_packets[3];
    let plaintext3 = open_packet(
        &mut recv_key,
        *pn3,
        direction,
        connection_id,
        additional_data,
        ciphertext3,
        512,
    ).expect(&format!("Failed to open packet {}", pn3));
    println!("  Packet {}: \"{}\" (✓ authenticated, used cached nonce key)",
             pn3, String::from_utf8_lossy(&plaintext3));
    println!();
    
    println!("=== Security Properties ===");
    println!("✓ Forward secrecy: Each packet uses unique nonce key NK^(e,pn)");
    println!("✓ Out-of-order support: Packets can arrive in any order (within window)");
    println!("✓ Authenticity: AES-GCM provides authentication tag");
    println!("✓ Confidentiality: Each packet encrypted with fresh per-packet key material");
    
    Ok(())
}
