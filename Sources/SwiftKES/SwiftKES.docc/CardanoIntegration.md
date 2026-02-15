# Cardano Integration

Using SwiftKES with Cardano blockchain infrastructure, including compatibility guarantees, key lifecycle management, and integration with cardano-node.

## Overview

SwiftKES is designed for byte-exact compatibility with Cardano's KES implementation. Cardano uses **Sum6KES** (Ed25519 sum-composition at depth 6) for block producer operational keys. This article covers how KES fits into Cardano's security model, the key lifecycle on a stake pool, and how to integrate SwiftKES with the broader Cardano tooling ecosystem.

## KES in Cardano

### Role of KES Keys

In Cardano's Ouroboros Praos protocol, each stake pool operator maintains three types of keys:

1. **Cold keys** (Ed25519) — The pool's long-lived identity key. Stored offline.
2. **KES keys** (Sum6KES) — The operational hot key used to sign blocks. Rotated every 64 KES periods.
3. **VRF keys** — Used for slot leader election. Not managed by SwiftKES.

The KES key is the only key that actively signs blocks. It is linked to the cold key through an **operational certificate** (OpCert), which authorizes a specific KES public key for a given range of KES periods.

### KES Period Mapping

On the Cardano mainnet, each KES period corresponds to a fixed number of slots (currently 129,600 slots, or approximately 1.5 days). With 64 periods per KES key, each key lasts approximately 96 days before it must be rotated.

```
KES Period = floor(current_slot / slots_per_kes_period)

With slots_per_kes_period = 129,600:
  Period 0: slots 0 – 129,599
  Period 1: slots 129,600 – 259,199
  ...
  Period 63: slots 8,294,400 – 8,423,999
```

The key must be evolved to match the current KES period before signing a block.

## Byte-Exact Compatibility

### Verified Components

SwiftKES produces byte-identical output to the Rust (`input-output-hk/kes`) and Haskell (`cardano-base`) implementations for:

| Component | Size | Status |
|-----------|------|--------|
| Secret Key (depth 0) | 32 bytes | Byte-exact match |
| Secret Key (depth 1) | 128 bytes | Byte-exact match |
| Secret Key (depth 6) | 608 bytes | Byte-exact match |
| Public Key | 32 bytes | Byte-exact match |
| Standard Signature | 448 bytes | Byte-exact match |
| Compact Signature | 288 bytes | Byte-exact match |
| Evolved Key (period 1) | 608 bytes | Byte-exact match |
| Evolved Key (period 5) | 608 bytes | Byte-exact match |

### Cryptographic Primitives

SwiftKES uses the same cryptographic primitives as the reference implementations:

- **Ed25519**: Signing and verification via libsodium (through [swift-ncal](https://github.com/Kingpin-Apps/swift-ncal))
- **Blake2b-256**: Seed splitting (with domain separation bytes `0x01` and `0x02`) and public key combination
- **Seed splitting**: `left = Blake2b-256(0x01 || seed)`, `right = Blake2b-256(0x02 || seed)`
- **Hash pair**: `pk = Blake2b-256(left_pk || right_pk)` with no domain separator

## Key Lifecycle

### 1. Generate a New KES Key

```swift
import SwiftKES
import Foundation

// Generate a cryptographically secure seed
var seed = Data(count: 32)
_ = seed.withUnsafeMutableBytes {
    SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
}

// Create the KES key pair
var kes = try Sum6KES(seed: seed)
let publicKey = kes.publicKey

// Zero the seed — it's no longer needed
seed.withUnsafeMutableBytes { bytes in
    bytes.initializeMemory(as: UInt8.self, repeating: 0)
}
```

### 2. Evolve to the Current Period

When starting a node, evolve the key to match the current KES period:

```swift
let currentKESPeriod: UInt = calculateCurrentKESPeriod()
let startPeriod = kes.currentPeriod

// Evolve to the current period
for _ in startPeriod..<currentKESPeriod {
    try kes.evolve()
}
```

### 3. Sign Blocks

When your pool is elected as a slot leader, sign the block header:

```swift
let blockHeader = buildBlockHeader()
let signature = try kes.sign(message: blockHeader)
```

### 4. Evolve at Period Boundaries

When the KES period advances, evolve the key:

```swift
let newPeriod = calculateCurrentKESPeriod()
if newPeriod > kes.currentPeriod {
    for _ in kes.currentPeriod..<newPeriod {
        try kes.evolve()
    }
    // Persist the updated key
    persistKey(kes.secretKeyBytes, period: kes.currentPeriod)
}
```

### 5. Rotate Before Exhaustion

Plan to generate a new KES key and operational certificate before period 63:

```swift
let remainingPeriods = Sum6KES.totalPeriods - kes.currentPeriod - 1
if remainingPeriods < 10 {
    // Time to generate a new KES key and issue a new OpCert
    let newSeed = generateSecureSeed()
    var newKES = try Sum6KES(seed: newSeed)
    // Issue new operational certificate with newKES.publicKey
    // ...
}
```

## Serialization

### Secret Key Format

Cardano stores KES secret keys as exactly **608 bytes** of raw key material. The signing period is **not** embedded in the key bytes — it must be tracked externally (typically in the node's state database).

```swift
// Export for storage
let rawBytes = kes.secretKeyBytes  // Exactly 608 bytes
let period = kes.currentPeriod

// Restore from storage
let restored = try Sum6KES(secretKeyBytes: rawBytes, period: period)
```

> Important: This differs from the Rust `kes` crate, which appends a 4-byte period to the key bytes. SwiftKES follows the Cardano node convention of storing raw bytes without the period suffix.

### Integration with swift-cardano

For full Cardano serialization support including TextEnvelope JSON format (`.skey`/`.vkey` files), CBOR encoding, and operational certificates, use the [swift-cardano](https://github.com/Kingpin-Apps/swift-cardano) package alongside SwiftKES.

## Using KESCore for Custom Depths

If you need KES at a different depth than 6, you can use ``KESCore`` directly:

```swift
// Generate a depth-4 key (16 periods)
let (sk, pk) = try KESCore.keygen(depth: 4, seed: seed)

// Sign at period 0
let sig = try KESCore.sign(depth: 4, sk: sk, period: 0, message: message)

// Verify
let valid = try KESCore.verify(depth: 4, pk: pk, period: 0, signature: sig, message: message)

// Evolve
try KESCore.update(depth: 4, sk: sk, currentPeriod: 0)
```

Use ``KESConstants`` to calculate sizes for arbitrary depths:

```swift
let depth = 4
let skSize = KESConstants.secretKeySize(depth: depth)   // 416 bytes
let sigSize = KESConstants.signatureSize(depth: depth)   // 320 bytes
let periods = KESConstants.totalPeriods(depth: depth)     // 16
```

## Further Reading

- <doc:GettingStarted> — Installation and basic usage
- <doc:SecurityGuide> — Forward security principles and key management
- [Cardano Developer Portal](https://developers.cardano.org/) — Official Cardano documentation
- [Ouroboros Praos Paper](https://eprint.iacr.org/2017/573) — The consensus protocol that uses KES
