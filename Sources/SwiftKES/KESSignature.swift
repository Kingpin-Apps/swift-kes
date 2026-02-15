import Foundation

/// A standard KES signature.
///
/// Layout for depth `N > 0`: `[child_sig | left_pk (32) | right_pk (32)]`
///
/// Layout for depth 0: just the 64-byte Ed25519 signature.
public struct KESSignature: Sendable, Equatable {

    /// Raw signature bytes.
    public let bytes: Data

    /// The depth of the KES tree that produced this signature.
    public let depth: Int

    /// Expected size for this depth.
    public var expectedSize: Int {
        KESConstants.signatureSize(depth: depth)
    }

    // MARK: - Initializers

    /// Create a signature from raw bytes at a given depth.
    ///
    /// - Parameters:
    ///   - depth: The tree depth.
    ///   - bytes: Raw signature data.
    /// - Throws: `KESError.invalidSize` on length mismatch.
    public init(depth: Int, bytes: Data) throws {
        let expected = KESConstants.signatureSize(depth: depth)
        guard bytes.count == expected else {
            throw KESError.invalidSize(
                expected: expected,
                actual: bytes.count,
                label: "KES signature at depth \(depth)"
            )
        }
        self.depth = depth
        self.bytes = bytes
    }

    // MARK: - Component accessors (depth > 0)

    /// Size of the child signature.
    private var childSigSize: Int {
        precondition(depth > 0)
        return KESConstants.signatureSize(depth: depth - 1)
    }

    /// The child (inner) signature bytes.
    public var childSignature: Data {
        precondition(depth > 0)
        return bytes.prefix(childSigSize)
    }

    /// The left (lhs) public key stored in the signature.
    public var leftPK: Data {
        precondition(depth > 0)
        let start = childSigSize
        return Data(bytes[start ..< start + KESConstants.publicKeySize])
    }

    /// The right (rhs) public key stored in the signature.
    public var rightPK: Data {
        precondition(depth > 0)
        let start = childSigSize + KESConstants.publicKeySize
        return Data(bytes[start ..< start + KESConstants.publicKeySize])
    }

    // MARK: - Builder

    /// Build a standard KES signature from its components.
    ///
    /// - Parameters:
    ///   - depth: The depth of this signature (must be > 0).
    ///   - childSig: The child signature bytes.
    ///   - lhsPK: Left public key (32 bytes).
    ///   - rhsPK: Right public key (32 bytes).
    /// - Returns: A new `KESSignature`.
    public static func build(
        depth: Int,
        childSig: Data,
        lhsPK: Data,
        rhsPK: Data
    ) throws -> KESSignature {
        precondition(depth > 0)
        let combined = childSig + lhsPK + rhsPK
        return try KESSignature(depth: depth, bytes: combined)
    }
}
