import Foundation

/// High-level Sum6KES (standard) key evolving signature scheme.
///
/// This is the scheme used by Cardano (`cardano-node`) for block production.
/// It supports 2^6 = 64 signing periods with forward security.
///
/// - Secret key: 608 bytes
/// - Public key: 32 bytes
/// - Signature: 448 bytes
///
/// ## Usage
///
/// ```swift
/// // Generate a new KES key pair from a random seed
/// let seed = Data(repeating: 0, count: 32) // use real entropy!
/// var kes = try Sum6KES(seed: seed)
///
/// // Sign at the current period (starts at 0)
/// let sig = try kes.sign(message: Data("hello".utf8))
///
/// // Verify
/// let valid = try Sum6KES.verify(
///     publicKey: kes.publicKey,
///     period: kes.currentPeriod,
///     signature: sig,
///     message: Data("hello".utf8)
/// )
///
/// // Evolve to the next period
/// try kes.evolve()
/// ```
public struct Sum6KES: @unchecked Sendable {

    // MARK: - Constants

    /// The tree depth.
    public static let depth: Int = 6

    /// Maximum number of signing periods (2^6 = 64).
    public static let totalPeriods: UInt = 64

    /// Secret key size in bytes.
    public static let secretKeySize: Int = 608

    /// Standard signature size in bytes.
    public static let signatureSize: Int = 448

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

    /// Generate a new Sum6KES key pair from a 32-byte seed.
    ///
    /// - Parameter seed: Exactly 32 bytes of entropy.
    /// - Throws: `KESError.invalidSeed` if the seed is not 32 bytes.
    public init(seed: Data) throws {
        let (sk, pk) = try KESCore.keygen(depth: Self.depth, seed: seed)
        self.sk = sk
        self.publicKey = pk
        self.currentPeriod = 0
    }

    /// Restore a Sum6KES key from its serialized secret key bytes and period.
    ///
    /// This is used for deserialization. The Cardano skey file stores only the
    /// 608-byte SK — the period must be tracked externally.
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
                label: "Sum6KES secret key"
            )
        }
        guard period < Self.totalPeriods else {
            throw KESError.periodOutOfRange(period: period, maxPeriod: Self.totalPeriods)
        }
        self.sk = try KESSecretKey(depth: Self.depth, bytes: secretKeyBytes)
        self.currentPeriod = period

        // Recompute the public key from the secret key state.
        // We need to derive it from the tree — at the top level the PK is
        // hash_pair(leftPK, rightPK).
        let compositeBytes = try HashPair.combine(sk.leftPK, sk.rightPK)
        self.publicKey = try KESPublicKey(bytes: compositeBytes)
    }

    // MARK: - Signing

    /// Sign a message at the current period.
    ///
    /// - Parameter message: The data to sign.
    /// - Returns: A standard 448-byte `KESSignature`.
    public func sign(message: Data) throws -> KESSignature {
        return try KESCore.sign(
            depth: Self.depth,
            sk: sk,
            period: currentPeriod,
            message: message
        )
    }

    // MARK: - Verification

    /// Verify a standard KES signature.
    ///
    /// - Parameters:
    ///   - publicKey: The KES public key.
    ///   - period: The period at which the signature was produced.
    ///   - signature: The standard KES signature.
    ///   - message: The original message.
    /// - Returns: `true` if the signature is valid.
    public static func verify(
        publicKey: KESPublicKey,
        period: UInt,
        signature: KESSignature,
        message: Data
    ) throws -> Bool {
        return try KESCore.verify(
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
    /// After calling this method, `currentPeriod` is incremented by 1.
    /// The old key material is securely zeroed for forward security.
    ///
    /// - Throws: `KESError.keyExhausted` if `currentPeriod >= 63`.
    public mutating func evolve() throws {
        try KESCore.update(depth: Self.depth, sk: sk, currentPeriod: currentPeriod)
        currentPeriod += 1
    }

    // MARK: - Serialization

    /// The raw 608-byte secret key data for serialization.
    ///
    /// The Cardano `.skey` file stores exactly 608 bytes — the period is NOT
    /// included (unlike the Rust crate which appends 4 bytes for the period).
    public var secretKeyBytes: Data {
        return sk.bytes
    }
}
