import Foundation

/// A KES public (verification) key — always 32 bytes (Blake2b-256 output).
///
/// For depth 0 this is the raw Ed25519 public key. For depth > 0 it is
/// `Blake2b-256( left_pk ‖ right_pk )`.
public struct KESPublicKey: Equatable, Hashable, Sendable {

    /// The raw 32-byte public key data.
    public let bytes: Data

    /// Create a KES public key from raw bytes.
    ///
    /// - Parameter bytes: Exactly 32 bytes.
    /// - Throws: `KESError.invalidSize` if the data is not 32 bytes.
    public init(bytes: Data) throws {
        guard bytes.count == KESConstants.publicKeySize else {
            throw KESError.invalidSize(
                expected: KESConstants.publicKeySize,
                actual: bytes.count,
                label: "KES public key"
            )
        }
        self.bytes = bytes
    }
}

extension KESPublicKey: CustomStringConvertible {
    public var description: String {
        "KESPublicKey(\(bytes.map { String(format: "%02x", $0) }.joined()))"
    }
}
