# Security Guide

Forward security principles, key management best practices, and security considerations for using SwiftKES safely.

## Overview

SwiftKES implements a forward-secure signature scheme where the primary security guarantee is that compromised keys cannot be used to forge signatures for past time periods. This guide covers how forward security works, how to manage keys safely, and common pitfalls to avoid.

## Forward Security

### How It Works

In a traditional digital signature scheme, a single signing key is used indefinitely. If that key is ever compromised, **all** signatures — past, present, and future — become suspect.

KES solves this by dividing the key's lifetime into discrete **periods**. At each period transition, the key material is updated and the old material is securely destroyed:

```
Period 0: [SK₀] → sign → evolve → zero SK₀
Period 1: [SK₁] → sign → evolve → zero SK₁
Period 2: [SK₂] → sign → ...
```

If an attacker obtains the key at period 2, they can forge signatures for periods 2 and later — but they **cannot** reconstruct SK₀ or SK₁. All signatures from periods 0 and 1 remain unforgeable.

### What Forward Security Protects Against

- **Key compromise**: A stolen key cannot forge past signatures
- **Server breach**: Historical block signatures remain valid after a node compromise
- **Insider threats**: A malicious operator who exfiltrates key material cannot rewrite history

### What Forward Security Does NOT Protect Against

- **Pre-compromise forgery**: If an attacker has the key before you use it, all periods are compromised
- **Current/future forgery**: A compromised key can sign for the current and all future periods
- **Side-channel attacks**: Forward security doesn't prevent key extraction through hardware or timing attacks

## Secure Key Generation

### Use Cryptographically Secure Seeds

The 32-byte seed is the root of all key material. It must come from a cryptographically secure random source:

```swift
import Foundation

// Use a secure random source
var seed = Data(count: 32)
let result = seed.withUnsafeMutableBytes {
    SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
}
guard result == errSecSuccess else {
    fatalError("Failed to generate secure random seed")
}

var kes = try Sum6KES(seed: seed)

// Zero the seed immediately after use
seed.withUnsafeMutableBytes { bytes in
    bytes.initializeMemory(as: UInt8.self, repeating: 0)
}
```

### Never Reuse Seeds

Each KES key pair must use a unique seed. Reusing a seed produces identical keys, which defeats forward security if one instance is evolved ahead of another:

```swift
// Never do this
let seed = Data(repeating: 0x42, count: 32)
var kes1 = try Sum6KES(seed: seed)
var kes2 = try Sum6KES(seed: seed)
// kes1 and kes2 have identical key material — dangerous!
```

### Never Use Predictable Seeds

Seeds derived from timestamps, counters, user input, or other predictable sources are insecure:

```swift
// Never derive seeds from predictable sources
let timestamp = Date().timeIntervalSince1970
var weakSeed = Data(count: 32)
// ... filling from timestamp — INSECURE!
```

## Secure Key Storage

### Secret Key Bytes

The ``Sum6KES/secretKeyBytes`` property returns the raw 608-byte secret key for serialization. This data must be protected at rest:

```swift
let skBytes = kes.secretKeyBytes // 608 bytes — treat as highly sensitive

// Store in a secure location:
// - iOS/macOS: Keychain with appropriate access controls
// - Server: Encrypted file with restricted permissions
// - HSM: Hardware security module for production deployments
```

### Period Tracking

The signing period is **not** stored within the secret key bytes. You must track it separately and store it alongside the key:

```swift
struct StoredKESKey {
    let secretKeyBytes: Data  // 608 bytes
    let currentPeriod: UInt   // Must be stored separately
}
```

> Warning: Using the wrong period when restoring a key will cause verification failures. Always store and restore the period alongside the key bytes.

### Keychain Storage (iOS/macOS)

For Apple platforms, use the Keychain for secure key storage:

```swift
import Security

func storeKESKey(_ keyBytes: Data, period: UInt, identifier: String) -> Bool {
    // Store secret key
    let keyQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "\(identifier)-sk",
        kSecValueData as String: keyBytes,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    let status = SecItemAdd(keyQuery as CFDictionary, nil)
    return status == errSecSuccess
}
```

## Memory Security

### Automatic Zeroing

``KESSecretKey`` is a reference type (`class`) that automatically zeroes all key material in its `deinit`:

```swift
func signAndForget(seed: Data, message: Data) throws -> KESSignature {
    var kes = try Sum6KES(seed: seed)
    let sig = try kes.sign(message: message)
    return sig
    // When kes goes out of scope, KESSecretKey.deinit zeroes the 608-byte buffer
}
```

### Seed Zeroing During Evolution

When a key evolves past the midpoint of any subtree, the stored seed for the right subtree is securely zeroed after it has been expanded:

```swift
try kes.evolve() // If this transitions to the right subtree,
                  // the stored seed is zeroed — it can never be recovered
```

This is critical for forward security: the seed that could regenerate previous-period key material is permanently destroyed.

### Avoid Unnecessary Copies

Be careful not to create copies of key material that bypass the automatic zeroing:

```swift
// Be cautious with this — the returned Data is a copy
let skBytes = kes.secretKeyBytes

// Zero it when you're done
var mutableBytes = skBytes
defer {
    mutableBytes.withUnsafeMutableBytes { bytes in
        bytes.initializeMemory(as: UInt8.self, repeating: 0)
    }
}
```

## Key Evolution Best Practices

### Evolve Promptly

Don't delay key evolution. The longer you hold a key at a given period, the larger the window for compromise:

```swift
// Sign, then immediately evolve
let sig = try kes.sign(message: blockData)
try kes.evolve()
// The old period's signing capability is now destroyed
```

### Handle Exhaustion Gracefully

A Sum6KES key supports exactly 64 periods (0 through 63). Plan for key rotation before exhaustion:

```swift
// Check remaining periods before signing
let remaining = Sum6KES.totalPeriods - kes.currentPeriod - 1
if remaining < 5 {
    // Trigger key rotation process
    print("Warning: only \(remaining) periods remaining")
}

if remaining == 0 {
    // This is the last period — must rotate after signing
}
```

### Never Skip Periods

Key evolution is strictly sequential. You cannot jump from period 0 to period 5 — you must call `evolve()` five times:

```swift
// Evolve to a target period
func evolveTo(kes: inout Sum6KES, targetPeriod: UInt) throws {
    while kes.currentPeriod < targetPeriod {
        try kes.evolve()
    }
}
```

## Verification Best Practices

### Always Verify Before Trusting

Never trust signed data without verification:

```swift
func processSignedBlock(
    blockData: Data,
    signature: KESSignature,
    publicKey: KESPublicKey,
    period: UInt
) throws -> Block {
    // Verify FIRST
    let valid = try Sum6KES.verify(
        publicKey: publicKey,
        period: period,
        signature: signature,
        message: blockData
    )

    guard valid else {
        throw BlockError.invalidSignature
    }

    // Only then process the block
    return try Block(data: blockData)
}
```

### Validate Period Bounds

Always check that a claimed period is within the valid range before attempting verification:

```swift
guard period < Sum6KES.totalPeriods else {
    throw BlockError.invalidPeriod
}
```

## Security Checklist

Before deploying applications using SwiftKES:

- [ ] Seeds are generated from a cryptographically secure random source
- [ ] Seeds are zeroed immediately after key generation
- [ ] Secret key bytes are stored in secure storage (Keychain, HSM, encrypted file)
- [ ] The signing period is tracked and stored alongside the key
- [ ] Keys are evolved promptly after each signing operation
- [ ] Key rotation is planned before the 64-period limit is reached
- [ ] All signatures are verified before trusting signed data
- [ ] Error handling doesn't leak sensitive key information
- [ ] No unnecessary copies of key material exist in memory
- [ ] The application has been reviewed by security professionals

## Further Reading

- <doc:GettingStarted> — Installation and basic usage
- <doc:CardanoIntegration> — Cardano-specific deployment considerations
- [Composing Forward-Secure Signatures](https://eprint.iacr.org/2001/034) — The original MMM construction paper
