import Foundation

/// Size constants and depth calculations for the KES sum-composition scheme.
///
/// The KES tree is a binary tree of depth `T`. At depth 0 the leaf is a single
/// Ed25519 key. Each additional depth level wraps two children, adding storage
/// for a seed and two public keys.
public enum KESConstants {

    // MARK: - Primitive sizes

    /// Size of a seed in bytes (Ed25519 / Blake2b-256).
    public static let seedSize: Int = 32

    /// Size of a KES public key (Blake2b-256 hash output).
    public static let publicKeySize: Int = 32

    /// Size of an Ed25519 signature.
    public static let ed25519SignatureSize: Int = 64

    /// Size of a libsodium Ed25519 secret key (seed ‖ public key).
    public static let ed25519SecretKeySize: Int = 64

    // MARK: - Depth-dependent sizes

    /// Secret key buffer size for a given depth.
    ///
    /// - `SK(0) = 32` (just the Ed25519 seed)
    /// - `SK(n) = SK(n-1) + 32 (seed) + 32 (left PK) + 32 (right PK) = SK(n-1) + 96`
    ///
    /// Concrete: 32, 128, 224, 320, 416, 512, **608** (depth 6)
    public static func secretKeySize(depth: Int) -> Int {
        precondition(depth >= 0, "Depth must be non-negative")
        if depth == 0 { return seedSize }
        return secretKeySize(depth: depth - 1) + seedSize + publicKeySize + publicKeySize
    }

    /// Standard signature size for a given depth.
    ///
    /// - `Sig(0) = 64` (Ed25519 signature)
    /// - `Sig(n) = Sig(n-1) + 32 (left PK) + 32 (right PK) = Sig(n-1) + 64`
    ///
    /// Concrete: 64, 128, 192, 256, 320, 384, **448** (depth 6)
    public static func signatureSize(depth: Int) -> Int {
        precondition(depth >= 0, "Depth must be non-negative")
        if depth == 0 { return ed25519SignatureSize }
        return signatureSize(depth: depth - 1) + publicKeySize + publicKeySize
    }

    /// Compact signature size for a given depth.
    ///
    /// `CompactSig(depth) = 64 + (depth + 1) * 32`
    ///
    /// At depth 0 the compact signature stores the Ed25519 sig (64) **plus** the
    /// Ed25519 public key (32) = 96 bytes. Each additional depth adds one sibling PK (32).
    ///
    /// Concrete: 96, 128, 160, 192, 224, 256, **288** (depth 6)
    public static func compactSignatureSize(depth: Int) -> Int {
        precondition(depth >= 0, "Depth must be non-negative")
        return ed25519SignatureSize + (depth + 1) * publicKeySize
    }

    /// Total number of signing periods for a tree of the given depth.
    ///
    /// `totalPeriods(depth) = 2^depth`
    public static func totalPeriods(depth: Int) -> UInt {
        precondition(depth >= 0 && depth <= 63, "Depth must be in [0, 63]")
        return UInt(1) << depth
    }
}
