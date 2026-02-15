# SwiftKES

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Swift 6.2+](https://img.shields.io/badge/Swift-6.2+-orange.svg)](https://swift.org)

A Swift implementation of **KES (Key Evolving Signatures)** — the forward-secure signature scheme used by Cardano for block production.

SwiftKES implements the **Sum6KES** construction (Sum-composition at depth 6) supporting 64 signing periods. Keys evolve forward through time periods, cryptographically destroying the ability to sign for past periods. This package is **binary-compatible** with `cardano-cli` and `cardano-node`, ported from the Rust [`input-output-hk/kes`](https://github.com/input-output-hk/kes) and Haskell [`cardano-base`](https://github.com/IntersectMBO/cardano-base) implementations.

## Features

- **Sum6KES** — Standard signatures (448 bytes) with full Cardano compatibility
- **Sum6CompactKES** — Compact signatures (288 bytes) for reduced storage
- **Forward Security** — Secure key zeroing on evolution; old periods become unsignable
- **Swift Concurrency** — All types are `Sendable` for Swift 6 strict concurrency
- **Byte-Exact Compatibility** — Validated against Rust test vectors

## Installation

Add SwiftKES to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-kes.git", from: "1.0.0"),
],
targets: [
    .target(
        name: "MyTarget",
        dependencies: [
            .product(name: "SwiftKES", package: "swift-kes"),
        ]
    ),
]
```

**Requirements:**
- Swift 6.2+
- iOS 14+ / macOS 14+ / watchOS 7+ / tvOS 14+

## Quick Start

### Generate, Sign, and Verify

```swift
import SwiftKES
import Foundation

// Generate a new KES key pair from a 32-byte seed
let seed = Data(repeating: 0, count: 32) // Use real entropy in production!
var kes = try Sum6KES(seed: seed)

// Sign a message at the current period (starts at 0)
let message = Data("Hello, Cardano!".utf8)
let signature = try kes.sign(message: message)

// Verify the signature
let isValid = try Sum6KES.verify(
    publicKey: kes.publicKey,
    period: kes.currentPeriod,
    signature: signature,
    message: message
)
// isValid == true
```

### Key Evolution

```swift
// Evolve the key to the next period
// Old signing capability is cryptographically destroyed
try kes.evolve()
// kes.currentPeriod is now 1

// Sign at the new period
let sig1 = try kes.sign(message: message)

// Continue evolving through all 64 periods (0-63)
for _ in 2..<64 {
    try kes.evolve()
}

// Attempting to evolve past period 63 throws KESError.keyExhausted
```

## Compact Signatures

`Sum6CompactKES` uses the same keys but produces smaller signatures (288 bytes vs 448 bytes) by storing only sibling public keys instead of both left and right:

```swift
var compact = try Sum6CompactKES(seed: seed)

let compactSig = try compact.sign(message: message)
// compactSig.bytes.count == 288 (vs 448 for standard)

let valid = try Sum6CompactKES.verify(
    publicKey: compact.publicKey,
    period: compact.currentPeriod,
    signature: compactSig,
    message: message
)

try compact.evolve()
```

Both variants share the same key generation — the same seed produces the same public key.

## Serialization

```swift
// Export raw bytes
let skBytes = kes.secretKeyBytes  // 608 bytes
let pkBytes = kes.publicKey.bytes // 32 bytes

// Restore from raw bytes (period must be tracked externally)
let restored = try Sum6KES(secretKeyBytes: skBytes, period: currentPeriod)
```

For Cardano-compatible TextEnvelope JSON serialization, CBOR encoding, and operational certificates, see the [swift-cardano](https://github.com/Kingpin-Apps/swift-cardano) package.

## Key Sizes

| Property | Standard (Sum6KES) | Compact (Sum6CompactKES) |
|----------|-------------------|--------------------------|
| Secret Key | 608 bytes | 608 bytes |
| Public Key | 32 bytes | 32 bytes |
| Signature | 448 bytes | 288 bytes |
| Total Periods | 64 (2^6) | 64 (2^6) |

## API Reference

### High-Level API

| Type | Description |
|------|-------------|
| `Sum6KES` | High-level Sum6KES with standard 448-byte signatures |
| `Sum6CompactKES` | High-level Sum6KES with compact 288-byte signatures |

### Data Types

| Type | Description |
|------|-------------|
| `KESPublicKey` | 32-byte verification key (Equatable, Hashable, Sendable) |
| `KESSecretKey` | Mutable secret key with secure zeroing on deallocation |
| `KESSignature` | Standard KES signature |
| `KESCompactSignature` | Compact KES signature |

### Low-Level & Utilities

| Type | Description |
|------|-------------|
| `KESCore` | Recursive KES algorithm engine (keygen, sign, verify, update) |
| `KESConstants` | Size calculations for arbitrary depths |
| `SeedSplitter` | Blake2b domain-separated seed splitting |
| `HashPair` | Public key combination via Blake2b |
| `KESError` | Error types for all KES operations |

## Security

- **Forward Security**: When a key is evolved to the next period, the old signing material is securely zeroed. An attacker who compromises a key cannot forge signatures for past periods.
- **Automatic Zeroing**: `KESSecretKey` is a reference type (`class`) whose `deinit` automatically zeroes all key material from memory.
- **Seed Destruction**: During key evolution at the midpoint transition, the stored seed for the right subtree is securely zeroed after expansion.

## Cardano Compatibility

SwiftKES produces byte-identical output to the Rust and Haskell implementations used by `cardano-node`:

- Secret keys, public keys, and signatures match byte-for-byte
- Validated with test vectors including byte-exact comparisons against [test vectors](https://github.com/input-output-hk/kes/tree/master/tests/data) from the Rust crate

## License

MIT License - Copyright (c) 2026 Kingpin Apps
