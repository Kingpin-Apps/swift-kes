import Foundation

/// High-level Sum6CompactKES — compact variant of the key evolving signature scheme.
///
/// Uses the same key generation and evolution as `Sum6KES` but produces smaller
/// signatures (288 bytes instead of 448) by storing only the sibling public key
/// at each tree level instead of both left and right.
///
/// - Secret key: 608 bytes (identical to Sum6KES)
/// - Public key: 32 bytes (identical to Sum6KES)
/// - Signature: 288 bytes (160 bytes smaller than standard)
///
/// Verification uses a bottom-up "recompute" algorithm.
public struct Sum6CompactKES: @unchecked Sendable {

    // MARK: - Constants

    /// The tree depth.
    public static let depth: Int = 6

    /// Maximum number of signing periods (2^6 = 64).
    public static let totalPeriods: UInt = 64

    /// Secret key size in bytes (same as standard).
    public static let secretKeySize: Int = 608

    /// Compact signature size in bytes.
    public static let signatureSize: Int = 288

    /// Public key size in bytes.
    public static let publicKeySize: Int = 32

    // MARK: - Properties

    /// The KES public (verification) key. Remains constant across all periods.
    public let publicKey: KESPublicKey

    /// The current signing period (0-based).
    public private(set) var currentPeriod: UInt

    /// The internal secret key state.
    private let sk: KESSecretKey

    // MARK: - Initializers

    /// Generate a new Sum6CompactKES key pair from a 32-byte seed.
    ///
    /// - Parameter seed: Exactly 32 bytes of entropy.
    /// - Throws: `KESError.invalidSeed` if the seed is not 32 bytes.
    public init(seed: Data) throws {
        let (sk, pk) = try KESCore.keygen(depth: Self.depth, seed: seed)
        self.sk = sk
        self.publicKey = pk
        self.currentPeriod = 0
    }

    /// Restore a Sum6CompactKES key from its serialized secret key bytes and period.
    ///
    /// - Parameters:
    ///   - secretKeyBytes: Exactly 608 bytes.
    ///   - period: The current period for this key.
    /// - Throws: On invalid sizes.
    public init(secretKeyBytes: Data, period: UInt) throws {
        guard secretKeyBytes.count == Self.secretKeySize else {
            throw KESError.invalidSize(
                expected: Self.secretKeySize,
                actual: secretKeyBytes.count,
                label: "Sum6CompactKES secret key"
            )
        }
        guard period < Self.totalPeriods else {
            throw KESError.periodOutOfRange(period: period, maxPeriod: Self.totalPeriods)
        }
        self.sk = try KESSecretKey(depth: Self.depth, bytes: secretKeyBytes)
        self.currentPeriod = period

        let compositeBytes = try HashPair.combine(sk.leftPK, sk.rightPK)
        self.publicKey = try KESPublicKey(bytes: compositeBytes)
    }

    // MARK: - Signing

    /// Sign a message at the current period with a compact signature.
    ///
    /// - Parameter message: The data to sign.
    /// - Returns: A compact 288-byte `KESCompactSignature`.
    public func sign(message: Data) throws -> KESCompactSignature {
        return try KESCore.signCompact(
            depth: Self.depth,
            sk: sk,
            period: currentPeriod,
            message: message
        )
    }

    // MARK: - Verification

    /// Verify a compact KES signature.
    ///
    /// - Parameters:
    ///   - publicKey: The KES public key.
    ///   - period: The period at which the signature was produced.
    ///   - signature: The compact KES signature.
    ///   - message: The original message.
    /// - Returns: `true` if the signature is valid.
    public static func verify(
        publicKey: KESPublicKey,
        period: UInt,
        signature: KESCompactSignature,
        message: Data
    ) throws -> Bool {
        return try KESCore.verifyCompact(
            depth: Self.depth,
            pk: publicKey,
            period: period,
            signature: signature,
            message: message
        )
    }

    // MARK: - Key Evolution

    /// Evolve the key to the next period.
    ///
    /// - Throws: `KESError.keyExhausted` if `currentPeriod >= 63`.
    public mutating func evolve() throws {
        try KESCore.update(depth: Self.depth, sk: sk, currentPeriod: currentPeriod)
        currentPeriod += 1
    }

    // MARK: - Serialization

    /// The raw 608-byte secret key data for serialization.
    public var secretKeyBytes: Data {
        return sk.bytes
    }
}
