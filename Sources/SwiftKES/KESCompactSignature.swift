import Foundation

/// A compact KES signature.
///
/// The compact variant stores only the sibling public key at each tree level
/// (rather than both left and right), saving space. Verification uses a
/// bottom-up `recompute` algorithm.
///
/// Layout for depth 0: `[ed25519_sig (64) | ed25519_pk (32)]` = 96 bytes.
///
/// Layout for depth N > 0: `[child_compact_sig | sibling_pk (32)]`.
///
/// Total size: `64 + (depth + 1) * 32`.
public struct KESCompactSignature: Sendable, Equatable {

    /// Raw compact signature bytes.
    public let bytes: Data

    /// The depth of the KES tree that produced this signature.
    public let depth: Int

    /// Expected size for this depth.
    public var expectedSize: Int {
        KESConstants.compactSignatureSize(depth: depth)
    }

    // MARK: - Initializers

    /// Create a compact signature from raw bytes at a given depth.
    ///
    /// - Parameters:
    ///   - depth: The tree depth.
    ///   - bytes: Raw compact signature data.
    /// - Throws: `KESError.invalidSize` on length mismatch.
    public init(depth: Int, bytes: Data) throws {
        let expected = KESConstants.compactSignatureSize(depth: depth)
        guard bytes.count == expected else {
            throw KESError.invalidSize(
                expected: expected,
                actual: bytes.count,
                label: "KES compact signature at depth \(depth)"
            )
        }
        self.depth = depth
        self.bytes = bytes
    }

    // MARK: - Depth 0 accessors

    /// The Ed25519 signature (64 bytes) — only valid at depth 0.
    public var ed25519Signature: Data {
        precondition(depth == 0)
        return Data(bytes.prefix(KESConstants.ed25519SignatureSize))
    }

    /// The Ed25519 public key (32 bytes) — only valid at depth 0.
    public var ed25519PublicKey: Data {
        precondition(depth == 0)
        let start = KESConstants.ed25519SignatureSize
        return Data(bytes[start ..< start + KESConstants.publicKeySize])
    }

    // MARK: - Depth > 0 accessors

    /// Size of the child compact signature.
    private var childCompactSigSize: Int {
        precondition(depth > 0)
        return KESConstants.compactSignatureSize(depth: depth - 1)
    }

    /// The child compact signature bytes.
    public var childSignature: Data {
        precondition(depth > 0)
        return Data(bytes.prefix(childCompactSigSize))
    }

    /// The sibling public key stored in the compact signature.
    public var siblingPK: Data {
        precondition(depth > 0)
        let start = childCompactSigSize
        return Data(bytes[start ..< start + KESConstants.publicKeySize])
    }

    // MARK: - Builders

    /// Build a compact signature at depth 0.
    ///
    /// - Parameters:
    ///   - ed25519Sig: The Ed25519 signature (64 bytes).
    ///   - ed25519PK: The Ed25519 public key (32 bytes).
    /// - Returns: A new `KESCompactSignature` at depth 0.
    public static func buildLeaf(
        ed25519Sig: Data,
        ed25519PK: Data
    ) throws -> KESCompactSignature {
        let combined = ed25519Sig + ed25519PK
        return try KESCompactSignature(depth: 0, bytes: combined)
    }

    /// Build a compact signature at depth > 0.
    ///
    /// - Parameters:
    ///   - depth: The tree depth (must be > 0).
    ///   - childSig: The child compact signature bytes.
    ///   - siblingPK: The sibling public key (32 bytes).
    /// - Returns: A new `KESCompactSignature`.
    public static func buildNode(
        depth: Int,
        childSig: Data,
        siblingPK: Data
    ) throws -> KESCompactSignature {
        precondition(depth > 0)
        let combined = childSig + siblingPK
        return try KESCompactSignature(depth: depth, bytes: combined)
    }
}
