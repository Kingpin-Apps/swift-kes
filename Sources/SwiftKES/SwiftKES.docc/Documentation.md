# ``SwiftKES``

A Swift implementation of Key Evolving Signatures (KES) — the forward-secure signature scheme used by Cardano for block production.

## Overview

SwiftKES implements the **Sum-composition Key Evolving Signature** scheme, providing forward security for cryptographic signing operations. In a KES scheme, signing keys evolve through discrete time periods. Once a key is evolved to the next period, the ability to sign for any previous period is **cryptographically destroyed** — even if the current key material is compromised, past signatures remain unforgeable.

This package provides **Sum6KES** (depth 6, supporting 64 signing periods) and its compact variant **Sum6CompactKES**, both binary-compatible with Cardano's `cardano-cli` and `cardano-node`. The implementation is ported from the Rust [input-output-hk/kes](https://github.com/input-output-hk/kes) and Haskell [cardano-base](https://github.com/IntersectMBO/cardano-base) implementations, validated byte-for-byte against their test vectors.

### Key Features

- **Forward Security**: Key evolution permanently destroys past signing capability
- **Sum6KES**: Standard signatures (448 bytes) with full Cardano compatibility
- **Sum6CompactKES**: Compact signatures (288 bytes) for reduced storage
- **Secure Memory**: Automatic key material zeroing on deallocation
- **Swift Concurrency**: All types conform to `Sendable` for safe concurrent use
- **Byte-Exact Compatibility**: Validated against Rust and Haskell test vectors

### How KES Works

KES uses a binary tree structure where each leaf represents a signing period. At depth 6, the tree has 2^6 = 64 leaves, giving 64 signing periods (0 through 63).

```
         Root (VK)
        /         \
      H01          H23
     /   \        /   \
   H0     H1    H2     H3
   /\     /\    /\     /\
  p0 p1  p2 p3 p4 p5  p6 p7   ← signing periods (depth 3 shown)
```

The **public verification key** is the root hash and never changes. The **secret signing key** contains the current subtree state and evolves forward through periods, securely zeroing old material at each step.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:SecurityGuide>
- <doc:CardanoIntegration>

### High-Level API

- ``Sum6KES``
- ``Sum6CompactKES``

### Keys and Signatures

- ``KESPublicKey``
- ``KESSecretKey``
- ``KESSignature``
- ``KESCompactSignature``

### Low-Level Algorithm Engine

- ``KESCore``

### Utilities

- ``KESConstants``
- ``SeedSplitter``
- ``HashPair``

### Error Handling

- ``KESError``
