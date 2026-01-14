# PCR-QUIC Integration Examples

This directory contains examples of integrating the `pcr-quic` crate with QUIC implementations.

## Example: Using pcr-quic with stock quiche

The standalone `pcr-quic` crate provides the cryptographic primitives for the double ratchet.
To use it with quiche, you need to integrate it into the packet protection layer.

See `quiche_integration/` for a reference implementation.

## Status

Currently, PCR-QUIC is integrated directly into quiche as a feature flag rather than
as an external crate dependency. This is because:

1. **Tight coupling**: PCR-QUIC needs access to quiche's internal packet protection APIs
2. **Performance**: Direct integration avoids extra indirection
3. **Development iteration**: Easier to modify both together

## Future Work

To use the standalone `pcr-quic` crate:

1. Create a `pcr-quic-quiche` adapter crate that:
   - Depends on both `pcr-quic` and `quiche`
   - Implements `quiche::crypto::PacketKey` trait using PCR-QUIC primitives
   - Wraps `PcrCryptoContext` for epoch management

2. Modify quiche to accept pluggable crypto backends

3. Register PCR-QUIC as an alternative packet protection implementation
