# Getting Started with SwiftKES

Learn how to integrate SwiftKES into your project and perform key generation, signing, verification, and key evolution.

## Overview

SwiftKES provides Key Evolving Signatures (KES) for Swift applications. This guide walks you through installation, core concepts, and common usage patterns to get you up and running quickly.

## Installation

### Swift Package Manager

Add SwiftKES to your project using Swift Package Manager.

#### Using Xcode

1. Open your project in Xcode
2. Select `File` > `Add Package Dependencies`
3. Enter the repository URL: `https://github.com/Kingpin-Apps/swift-kes.git`
4. Choose the version or branch you want to use

#### Using Package.swift

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-kes.git", from: "1.0.0"),
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "SwiftKES", package: "swift-kes"),
        ]
    ),
]
```

### Platform Support

- **iOS** 14.0+
- **macOS** 14.0+
- **tvOS** 14.0+
- **watchOS** 7.0+

Requires **Swift 6.2** or later.

## Core Concepts

### What is KES?

Key Evolving Signatures (KES) is a forward-secure digital signature scheme. Unlike standard signatures where a single key signs for all time, KES keys **evolve** through a series of discrete periods. At each evolution step, the ability to sign for previous periods is cryptographically destroyed.

This means that if an attacker steals your current key, they can forge signatures for the current and future periods — but they **cannot** forge signatures for any past period. All historical signatures remain trustworthy.

### Periods and Depth

SwiftKES uses a Sum-composition tree at **depth 6**, which provides **64 signing periods** (2^6 = 64), numbered 0 through 63. Each key starts at period 0 and can be evolved forward one period at a time until period 63, at which point the key is exhausted.

### Standard vs Compact Signatures

SwiftKES provides two signature variants:

| Variant | Type | Signature Size | Use Case |
|---------|------|---------------|----------|
| Standard | ``Sum6KES`` | 448 bytes | Full Cardano node compatibility |
| Compact | ``Sum6CompactKES`` | 288 bytes | Reduced storage requirements |

Both variants use the **same keys** (608-byte secret key, 32-byte public key) and the same key generation and evolution algorithms. The same seed produces the same key pair for both variants. They differ only in how signatures are structured.

## Basic Usage

### Generate a Key Pair

Every KES operation starts with generating a key pair from a 32-byte seed:

```swift
import SwiftKES
import Foundation

// Generate a 32-byte seed (use real entropy in production!)
let seed = generateSecureRandomSeed() // Your secure random function

// Create a Sum6KES key pair
var kes = try Sum6KES(seed: seed)

// The public key is used for verification and never changes
let publicKey = kes.publicKey  // 32 bytes

// The key starts at period 0
print(kes.currentPeriod) // 0
```

### Sign a Message

Sign any data at the current period:

```swift
let message = Data("Block header data".utf8)
let signature = try kes.sign(message: message)
// signature.bytes.count == 448
```

### Verify a Signature

Verification uses the public key, the period at which the signature was created, and the original message:

```swift
let isValid = try Sum6KES.verify(
    publicKey: publicKey,
    period: 0,
    signature: signature,
    message: message
)
// isValid == true
```

### Evolve the Key

Move the key forward to the next period. This permanently destroys the ability to sign for the current period:

```swift
try kes.evolve()
// kes.currentPeriod is now 1

// Sign at the new period
let sig1 = try kes.sign(message: message)

// The old signature (period 0) is still verifiable with the same public key
let stillValid = try Sum6KES.verify(
    publicKey: publicKey,
    period: 0,
    signature: signature, // The signature from period 0
    message: message
)
// stillValid == true — past signatures remain valid!
```

## Complete Lifecycle Example

Here is a typical lifecycle showing key generation, signing across multiple periods, and exhaustion:

```swift
import SwiftKES
import Foundation

// 1. Generate key pair
let seed = Data(repeating: 0, count: 32) // Use real entropy!
var kes = try Sum6KES(seed: seed)
let vk = kes.publicKey

// 2. Sign and evolve through periods
var signatures: [(UInt, KESSignature)] = []

for period in 0..<UInt(Sum6KES.totalPeriods) {
    let msg = Data("Block at period \(period)".utf8)
    let sig = try kes.sign(message: msg)
    signatures.append((period, sig))

    // Evolve to next period (except at the last one)
    if period < Sum6KES.totalPeriods - 1 {
        try kes.evolve()
    }
}

// 3. Verify all signatures
for (period, sig) in signatures {
    let msg = Data("Block at period \(period)".utf8)
    let valid = try Sum6KES.verify(
        publicKey: vk,
        period: period,
        signature: sig,
        message: msg
    )
    assert(valid)
}

// 4. Key is now exhausted — further evolution throws
do {
    try kes.evolve()
} catch KESError.keyExhausted {
    print("Key exhausted after 64 periods — expected!")
}
```

## Using Compact Signatures

``Sum6CompactKES`` has the same API as ``Sum6KES`` but produces smaller signatures:

```swift
// Same seed produces the same public key
var compact = try Sum6CompactKES(seed: seed)
assert(compact.publicKey == kes.publicKey) // Same VK!

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

## Serialization

### Exporting and Restoring Keys

Export the raw secret key bytes for storage, and restore them later:

```swift
// Export
let skBytes = kes.secretKeyBytes  // 608 bytes
let period = kes.currentPeriod

// Store skBytes and period securely...

// Restore
let restored = try Sum6KES(secretKeyBytes: skBytes, period: period)
```

> Important: The period is **not** embedded in the secret key bytes. You must track and store it separately.

### Key Sizes Reference

| Component | Size |
|-----------|------|
| Seed | 32 bytes |
| Secret Key | 608 bytes |
| Public Key | 32 bytes |
| Standard Signature | 448 bytes |
| Compact Signature | 288 bytes |

## Error Handling

SwiftKES uses ``KESError`` for all error conditions. Always wrap operations in proper error handling:

```swift
do {
    var kes = try Sum6KES(seed: seed)
    let sig = try kes.sign(message: message)
    try kes.evolve()
} catch KESError.invalidSeed {
    print("Seed must be exactly 32 bytes")
} catch KESError.keyExhausted {
    print("Key has been evolved through all 64 periods")
} catch KESError.verificationFailed {
    print("Signature is invalid")
} catch KESError.periodOutOfRange(let period, let maxPeriod) {
    print("Period \(period) exceeds maximum \(maxPeriod)")
} catch {
    print("Unexpected error: \(error)")
}
```

## Thread Safety

All SwiftKES types conform to `Sendable` and are safe to use in concurrent contexts:

```swift
// Safe to pass across concurrency boundaries
let publicKey = kes.publicKey
let signature = try kes.sign(message: message)

Task {
    let valid = try Sum6KES.verify(
        publicKey: publicKey,
        period: 0,
        signature: signature,
        message: message
    )
}
```

> Note: ``KESSecretKey`` is a reference type (`class`) marked `@unchecked Sendable`. While the signing operations are safe, avoid mutating a single ``Sum6KES`` instance from multiple threads simultaneously. Key evolution (`evolve()`) should be called from a single owner.

## Next Steps

- **<doc:SecurityGuide>** — Forward security principles and key management best practices
- **<doc:CardanoIntegration>** — Using SwiftKES with Cardano blockchain infrastructure
- Browse the API reference for detailed documentation on each type and method
