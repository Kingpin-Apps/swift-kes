import Foundation

/// Errors specific to KES (Key Evolving Signature) operations.
public enum KESError: Error, Equatable, Sendable {
    /// The key has been evolved through all available periods and cannot be updated further.
    case keyExhausted

    /// The requested period is outside the valid range for this key depth.
    case periodOutOfRange(period: UInt, maxPeriod: UInt)

    /// Signature verification failed — the signature is invalid for the given message and key.
    case verificationFailed

    /// A data buffer has an unexpected size.
    case invalidSize(expected: Int, actual: Int, label: String)

    /// The provided seed is not exactly 32 bytes.
    case invalidSeed

    /// An internal cryptographic library error.
    case internalError(String)
}
