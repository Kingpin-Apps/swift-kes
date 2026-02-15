import Foundation
import SwiftNcal

/// Core recursive KES operations: key generation, signing, verification, and
/// key evolution for both standard and compact variants.
///
/// All functions are static and operate on the primitive data types defined in
/// this package. The high-level `Sum6KES` / `Sum6CompactKES` types delegate to
/// these functions.
///
/// The implementation matches the Rust `input-output-hk/kes` crate byte-for-byte.
public enum KESCore {

    // MARK: - Shared Sodium instance

    nonisolated(unsafe) private static let sodium = Sodium()

    // MARK: - Key Generation

    /// Generate a KES key pair from a 32-byte seed.
    ///
    /// - Parameters:
    ///   - depth: The tree depth (0 = Ed25519 leaf).
    ///   - seed: Exactly 32 bytes of entropy.
    /// - Returns: A `(secretKey, publicKey)` tuple.
    /// - Throws: On invalid seed or cryptographic failure.
    public static func keygen(
        depth: Int,
        seed: Data
    ) throws -> (sk: KESSecretKey, pk: KESPublicKey) {
        guard seed.count == KESConstants.seedSize else {
            throw KESError.invalidSeed
        }

        if depth == 0 {
            return try keygenLeaf(seed: seed)
        } else {
            return try keygenNode(depth: depth, seed: seed)
        }
    }

    /// Depth-0 keygen: Ed25519 keypair from seed.
    private static func keygenLeaf(
        seed: Data
    ) throws -> (sk: KESSecretKey, pk: KESPublicKey) {
        // Derive the Ed25519 public key from the seed.
        let keypair = try sodium.cryptoSign.seedKeypair(seed: seed)
        // SK buffer at depth 0 = the 32-byte seed itself.
        let sk = try KESSecretKey(depth: 0, bytes: seed)
        let pk = try KESPublicKey(bytes: keypair.publicKey)
        return (sk, pk)
    }

    /// Depth > 0 keygen: split seed, recursively generate children.
    private static func keygenNode(
        depth: Int,
        seed: Data
    ) throws -> (sk: KESSecretKey, pk: KESPublicKey) {
        // 1. Split the seed into left and right
        let (leftSeed, rightSeed) = try SeedSplitter.split(seed: seed)

        // 2. Recursively generate the left child (full SK + PK)
        let (leftSK, leftPK) = try keygen(depth: depth - 1, seed: leftSeed)

        // 3. Recursively generate the right child (only need the PK)
        let (_, rightPK) = try keygen(depth: depth - 1, seed: rightSeed)

        // 4. Build the buffer: [left_child_sk | right_seed | left_pk | right_pk]
        var buffer = Data()
        buffer.append(leftSK.bytes)
        buffer.append(rightSeed)
        buffer.append(leftPK.bytes)
        buffer.append(rightPK.bytes)

        let sk = try KESSecretKey(depth: depth, bytes: buffer)

        // 5. Composite public key = hash_pair(left_pk, right_pk)
        let compositeBytes = try HashPair.combine(leftPK.bytes, rightPK.bytes)
        let pk = try KESPublicKey(bytes: compositeBytes)

        return (sk, pk)
    }

    // MARK: - Standard Signing

    /// Sign a message with a KES secret key at the given period.
    ///
    /// - Parameters:
    ///   - depth: The tree depth.
    ///   - sk: The secret key.
    ///   - period: The current signing period (0-based).
    ///   - message: The message to sign.
    /// - Returns: A standard `KESSignature`.
    /// - Throws: On invalid period, key exhaustion, or cryptographic failure.
    public static func sign(
        depth: Int,
        sk: KESSecretKey,
        period: UInt,
        message: Data
    ) throws -> KESSignature {
        let maxPeriod = KESConstants.totalPeriods(depth: depth)
        guard period < maxPeriod else {
            throw KESError.periodOutOfRange(period: period, maxPeriod: maxPeriod)
        }

        if depth == 0 {
            return try signLeaf(sk: sk, message: message)
        } else {
            return try signNode(depth: depth, sk: sk, period: period, message: message)
        }
    }

    /// Depth 0: Ed25519 sign.
    private static func signLeaf(
        sk: KESSecretKey,
        message: Data
    ) throws -> KESSignature {
        // Reconstruct the full 64-byte libsodium SK (seed + pk)
        let keypair = try sodium.cryptoSign.seedKeypair(seed: sk.bytes)
        // crypto_sign returns sig(64) + message
        let signed = try sodium.cryptoSign.sign(message: message, sk: keypair.secretKey)
        let sig = Data(signed.prefix(KESConstants.ed25519SignatureSize))
        return try KESSignature(depth: 0, bytes: sig)
    }

    /// Depth > 0: navigate tree, recursively sign, append public keys.
    private static func signNode(
        depth: Int,
        sk: KESSecretKey,
        period: UInt,
        message: Data
    ) throws -> KESSignature {
        let half = KESConstants.totalPeriods(depth: depth - 1)

        // Extract child SK
        let childSKData = sk.childSK
        let childSK = try KESSecretKey(depth: depth - 1, bytes: childSKData)

        let childSig: KESSignature
        if period < half {
            // Left subtree
            childSig = try sign(depth: depth - 1, sk: childSK, period: period, message: message)
        } else {
            // Right subtree (adjust period)
            childSig = try sign(depth: depth - 1, sk: childSK, period: period - half, message: message)
        }

        // Build: [child_sig | left_pk | right_pk]
        return try KESSignature.build(
            depth: depth,
            childSig: childSig.bytes,
            lhsPK: sk.leftPK,
            rhsPK: sk.rightPK
        )
    }

    // MARK: - Standard Verification

    /// Verify a standard KES signature.
    ///
    /// - Parameters:
    ///   - depth: The tree depth.
    ///   - pk: The expected public key.
    ///   - period: The period at which the signature was produced.
    ///   - signature: The standard KES signature.
    ///   - message: The original message.
    /// - Returns: `true` if the signature is valid.
    /// - Throws: On invalid sizes or cryptographic failure.
    public static func verify(
        depth: Int,
        pk: KESPublicKey,
        period: UInt,
        signature: KESSignature,
        message: Data
    ) throws -> Bool {
        let maxPeriod = KESConstants.totalPeriods(depth: depth)
        guard period < maxPeriod else {
            return false
        }

        if depth == 0 {
            return try verifyLeaf(pk: pk, signature: signature, message: message)
        } else {
            return try verifyNode(depth: depth, pk: pk, period: period, signature: signature, message: message)
        }
    }

    /// Depth 0: Ed25519 verify.
    private static func verifyLeaf(
        pk: KESPublicKey,
        signature: KESSignature,
        message: Data
    ) throws -> Bool {
        // Reconstruct NaCl "signed message": sig(64) + message
        let signed = signature.bytes + message
        do {
            _ = try sodium.cryptoSign.open(signed: signed, pk: pk.bytes)
            return true
        } catch {
            return false
        }
    }

    /// Depth > 0: check hash_pair, then recurse.
    private static func verifyNode(
        depth: Int,
        pk: KESPublicKey,
        period: UInt,
        signature: KESSignature,
        message: Data
    ) throws -> Bool {
        // 1. Verify that hash_pair(lhs_pk, rhs_pk) == expected pk
        let recomputed = try HashPair.combine(signature.leftPK, signature.rightPK)
        guard recomputed == pk.bytes else {
            return false
        }

        let half = KESConstants.totalPeriods(depth: depth - 1)
        let childSig = try KESSignature(depth: depth - 1, bytes: signature.childSignature)

        if period < half {
            let childPK = try KESPublicKey(bytes: signature.leftPK)
            return try verify(depth: depth - 1, pk: childPK, period: period, signature: childSig, message: message)
        } else {
            let childPK = try KESPublicKey(bytes: signature.rightPK)
            return try verify(depth: depth - 1, pk: childPK, period: period - half, signature: childSig, message: message)
        }
    }

    // MARK: - Key Evolution (Update)

    /// Evolve the secret key from `currentPeriod` to `currentPeriod + 1`.
    ///
    /// This mutates the `KESSecretKey` buffer in place, zeroing old key material
    /// to provide forward security.
    ///
    /// - Parameters:
    ///   - depth: The tree depth.
    ///   - sk: The secret key to evolve (mutated in place).
    ///   - currentPeriod: The period the key is currently at.
    /// - Throws: `KESError.keyExhausted` if the key cannot be evolved further.
    public static func update(
        depth: Int,
        sk: KESSecretKey,
        currentPeriod: UInt
    ) throws {
        let total = KESConstants.totalPeriods(depth: depth)
        let nextPeriod = currentPeriod + 1

        guard nextPeriod < total else {
            throw KESError.keyExhausted
        }

        if depth == 0 {
            // Depth 0 has only one period — cannot update.
            throw KESError.keyExhausted
        }

        let half = KESConstants.totalPeriods(depth: depth - 1)

        if nextPeriod < half {
            // Still in the left subtree — recursively update the child.
            let childSK = try KESSecretKey(depth: depth - 1, bytes: Data(sk.childSK))
            try update(depth: depth - 1, sk: childSK, currentPeriod: currentPeriod)
            sk.setChildSK(childSK.bytes)

        } else if nextPeriod == half {
            // Transition point: expand the right subtree from the stored seed.
            let rightSeed = Data(sk.storedSeed)
            let (rightSK, _) = try keygen(depth: depth - 1, seed: rightSeed)

            // Replace child SK with the right child's SK
            sk.setChildSK(rightSK.bytes)

            // Zero the stored seed — it's no longer needed (forward security).
            sk.zeroStoredSeed()

        } else {
            // In the right subtree — recursively update the child.
            let childSK = try KESSecretKey(depth: depth - 1, bytes: Data(sk.childSK))
            try update(depth: depth - 1, sk: childSK, currentPeriod: currentPeriod - half)
            sk.setChildSK(childSK.bytes)
        }
    }

    // MARK: - Compact Signing

    /// Sign a message with a compact KES signature.
    ///
    /// The compact variant stores only the sibling PK at each level,
    /// reducing the signature size.
    ///
    /// - Parameters:
    ///   - depth: The tree depth.
    ///   - sk: The secret key.
    ///   - period: The current signing period.
    ///   - message: The message to sign.
    /// - Returns: A `KESCompactSignature`.
    public static func signCompact(
        depth: Int,
        sk: KESSecretKey,
        period: UInt,
        message: Data
    ) throws -> KESCompactSignature {
        let maxPeriod = KESConstants.totalPeriods(depth: depth)
        guard period < maxPeriod else {
            throw KESError.periodOutOfRange(period: period, maxPeriod: maxPeriod)
        }

        if depth == 0 {
            return try signCompactLeaf(sk: sk, message: message)
        } else {
            return try signCompactNode(depth: depth, sk: sk, period: period, message: message)
        }
    }

    /// Depth 0 compact: Ed25519 sig + Ed25519 pk.
    private static func signCompactLeaf(
        sk: KESSecretKey,
        message: Data
    ) throws -> KESCompactSignature {
        let keypair = try sodium.cryptoSign.seedKeypair(seed: sk.bytes)
        let signed = try sodium.cryptoSign.sign(message: message, sk: keypair.secretKey)
        let sig = Data(signed.prefix(KESConstants.ed25519SignatureSize))
        return try KESCompactSignature.buildLeaf(ed25519Sig: sig, ed25519PK: keypair.publicKey)
    }

    /// Depth > 0 compact: recurse, attach sibling PK.
    private static func signCompactNode(
        depth: Int,
        sk: KESSecretKey,
        period: UInt,
        message: Data
    ) throws -> KESCompactSignature {
        let half = KESConstants.totalPeriods(depth: depth - 1)
        let childSKData = sk.childSK
        let childSK = try KESSecretKey(depth: depth - 1, bytes: childSKData)

        let childSig: KESCompactSignature
        let siblingPK: Data

        if period < half {
            childSig = try signCompact(depth: depth - 1, sk: childSK, period: period, message: message)
            siblingPK = Data(sk.rightPK)  // Sibling is right
        } else {
            childSig = try signCompact(depth: depth - 1, sk: childSK, period: period - half, message: message)
            siblingPK = Data(sk.leftPK)   // Sibling is left
        }

        return try KESCompactSignature.buildNode(
            depth: depth,
            childSig: childSig.bytes,
            siblingPK: siblingPK
        )
    }

    // MARK: - Compact Verification

    /// Verify a compact KES signature.
    ///
    /// Uses the bottom-up `recompute` algorithm to rebuild the root public key
    /// from the signature and compare it with the expected key.
    ///
    /// - Parameters:
    ///   - depth: The tree depth.
    ///   - pk: The expected public key.
    ///   - period: The period at which the signature was produced.
    ///   - signature: The compact KES signature.
    ///   - message: The original message.
    /// - Returns: `true` if valid.
    public static func verifyCompact(
        depth: Int,
        pk: KESPublicKey,
        period: UInt,
        signature: KESCompactSignature,
        message: Data
    ) throws -> Bool {
        let maxPeriod = KESConstants.totalPeriods(depth: depth)
        guard period < maxPeriod else {
            return false
        }

        do {
            let recomputed = try recompute(depth: depth, period: period, signature: signature, message: message)
            return recomputed == pk.bytes
        } catch {
            return false
        }
    }

    /// Bottom-up recomputation of the root PK from a compact signature.
    ///
    /// - Returns: The recomputed 32-byte public key.
    /// - Throws: `KESError.verificationFailed` if the Ed25519 base signature is invalid.
    private static func recompute(
        depth: Int,
        period: UInt,
        signature: KESCompactSignature,
        message: Data
    ) throws -> Data {
        if depth == 0 {
            return try recomputeLeaf(signature: signature, message: message)
        } else {
            return try recomputeNode(depth: depth, period: period, signature: signature, message: message)
        }
    }

    /// Depth 0 recompute: verify Ed25519, return the embedded public key.
    private static func recomputeLeaf(
        signature: KESCompactSignature,
        message: Data
    ) throws -> Data {
        let sig = signature.ed25519Signature
        let pk = signature.ed25519PublicKey

        // Verify the Ed25519 signature
        let signed = sig + message
        do {
            _ = try sodium.cryptoSign.open(signed: signed, pk: pk)
        } catch {
            throw KESError.verificationFailed
        }

        return pk
    }

    /// Depth > 0 recompute: recurse, then hash_pair with the sibling PK.
    private static func recomputeNode(
        depth: Int,
        period: UInt,
        signature: KESCompactSignature,
        message: Data
    ) throws -> Data {
        let half = KESConstants.totalPeriods(depth: depth - 1)
        let childSig = try KESCompactSignature(depth: depth - 1, bytes: signature.childSignature)

        if period < half {
            // Signing was in the left subtree; sibling is the right PK
            let childPK = try recompute(depth: depth - 1, period: period, signature: childSig, message: message)
            return try HashPair.combine(childPK, signature.siblingPK)
        } else {
            // Signing was in the right subtree; sibling is the left PK
            let childPK = try recompute(depth: depth - 1, period: period - half, signature: childSig, message: message)
            return try HashPair.combine(signature.siblingPK, childPK)
        }
    }
}
