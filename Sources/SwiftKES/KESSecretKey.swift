import Foundation

/// Mutable, reference-type container for a KES secret key buffer.
///
/// The buffer layout for depth `N > 0` is:
/// ```
/// ┌──────────────────────┬───────────┬──────────┬──────────┐
/// │ child SK             │ seed (32) │ left PK  │ right PK │
/// │ (secretKeySize(N-1)) │           │ (32)     │ (32)     │
/// └──────────────────────┴───────────┴──────────┴──────────┘
/// ```
///
/// For depth 0 the buffer is just the 32-byte Ed25519 seed.
///
/// This is a `class` (reference type) so that:
/// 1. Forward-security zeroing is performed in-place.
/// 2. The `update` operation mutates the buffer without copies.
/// 3. `deinit` can zero all bytes for defense-in-depth.
public final class KESSecretKey: @unchecked Sendable {

    /// The depth of the KES tree this key belongs to.
    public let depth: Int

    /// The raw key buffer. Size = `KESConstants.secretKeySize(depth:)`.
    internal var bytes: Data

    /// The expected total size for this depth.
    public var expectedSize: Int {
        KESConstants.secretKeySize(depth: depth)
    }

    // MARK: - Initializers

    /// Create a secret key from raw bytes at a given depth.
    ///
    /// - Parameters:
    ///   - depth: The tree depth.
    ///   - bytes: Raw key data whose length must equal `secretKeySize(depth:)`.
    /// - Throws: `KESError.invalidSize` on length mismatch.
    public init(depth: Int, bytes: Data) throws {
        let expected = KESConstants.secretKeySize(depth: depth)
        guard bytes.count == expected else {
            throw KESError.invalidSize(
                expected: expected,
                actual: bytes.count,
                label: "KES secret key at depth \(depth)"
            )
        }
        self.depth = depth
        self.bytes = bytes
    }

    deinit {
        zeroAll()
    }

    // MARK: - Layout accessors (depth > 0 only)

    /// Size of the child secret key.
    private var childSize: Int {
        precondition(depth > 0, "No child at depth 0")
        return KESConstants.secretKeySize(depth: depth - 1)
    }

    /// The child (left-subtree) secret key bytes.
    public var childSK: Data {
        precondition(depth > 0)
        return bytes.prefix(childSize)
    }

    /// The stored seed for the right subtree (32 bytes after child SK).
    public var storedSeed: Data {
        precondition(depth > 0)
        let start = childSize
        return bytes[start ..< start + KESConstants.seedSize]
    }

    /// The left public key (32 bytes).
    public var leftPK: Data {
        precondition(depth > 0)
        let start = childSize + KESConstants.seedSize
        return bytes[start ..< start + KESConstants.publicKeySize]
    }

    /// The right public key (32 bytes).
    public var rightPK: Data {
        precondition(depth > 0)
        let start = childSize + KESConstants.seedSize + KESConstants.publicKeySize
        return bytes[start ..< start + KESConstants.publicKeySize]
    }

    // MARK: - Mutation

    /// Replace the child SK region with new data.
    public func setChildSK(_ data: Data) {
        precondition(depth > 0)
        precondition(data.count == childSize)
        bytes.replaceSubrange(0 ..< childSize, with: data)
    }

    /// Replace the stored seed region with new data.
    public func setStoredSeed(_ data: Data) {
        precondition(depth > 0)
        precondition(data.count == KESConstants.seedSize)
        let start = childSize
        bytes.replaceSubrange(start ..< start + KESConstants.seedSize, with: data)
    }

    /// Replace the left PK region.
    public func setLeftPK(_ data: Data) {
        precondition(depth > 0)
        precondition(data.count == KESConstants.publicKeySize)
        let start = childSize + KESConstants.seedSize
        bytes.replaceSubrange(start ..< start + KESConstants.publicKeySize, with: data)
    }

    /// Replace the right PK region.
    public func setRightPK(_ data: Data) {
        precondition(depth > 0)
        precondition(data.count == KESConstants.publicKeySize)
        let start = childSize + KESConstants.seedSize + KESConstants.publicKeySize
        bytes.replaceSubrange(start ..< start + KESConstants.publicKeySize, with: data)
    }

    /// Zero-fill the stored seed region (forward security).
    public func zeroStoredSeed() {
        precondition(depth > 0)
        let start = childSize
        bytes.replaceSubrange(
            start ..< start + KESConstants.seedSize,
            with: Data(count: KESConstants.seedSize)
        )
    }

    /// Zero-fill the entire buffer.
    public func zeroAll() {
        bytes.resetBytes(in: 0 ..< bytes.count)
    }
}
