import Foundation
import SwiftNaCl

/// Public key combination via Blake2b hashing.
///
/// Computes `Blake2b-256( left_pk ‖ right_pk )` with **no** domain separator,
/// matching the Rust `PublicKey::hash_pair` in `input-output-hk/kes`.
public enum HashPair {

    /// Combine two 32-byte public keys into a single 32-byte composite key.
    ///
    /// - Parameters:
    ///   - lhs: Left public key (32 bytes).
    ///   - rhs: Right public key (32 bytes).
    /// - Returns: The 32-byte Blake2b hash of the concatenation.
    /// - Throws: `KESError.invalidSize` if either key is not 32 bytes.
    public static func combine(_ lhs: Data, _ rhs: Data) throws -> Data {
        guard lhs.count == KESConstants.publicKeySize else {
            throw KESError.invalidSize(
                expected: KESConstants.publicKeySize,
                actual: lhs.count,
                label: "left public key in hash_pair"
            )
        }
        guard rhs.count == KESConstants.publicKeySize else {
            throw KESError.invalidSize(
                expected: KESConstants.publicKeySize,
                actual: rhs.count,
                label: "right public key in hash_pair"
            )
        }

        let sodium = Sodium()
        return try sodium.cryptoGenericHash.blake2bSaltPersonal(
            data: lhs + rhs,
            digestSize: KESConstants.publicKeySize
        )
    }
}
