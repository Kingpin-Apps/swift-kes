import Foundation
import SwiftNaCl

/// Deterministic seed splitting using Blake2b with domain separation.
///
/// Given a 32-byte seed, produces two independent 32-byte child seeds:
/// ```
/// left_seed  = Blake2b-256( 0x01 ‖ seed )
/// right_seed = Blake2b-256( 0x02 ‖ seed )
/// ```
///
/// This matches the Rust `Seed::split_slice` in `input-output-hk/kes`.
public enum SeedSplitter {

    /// Split a 32-byte seed into left and right child seeds.
    ///
    /// - Parameter seed: Exactly 32 bytes of entropy.
    /// - Returns: A tuple of `(left, right)` seeds, each 32 bytes.
    /// - Throws: `KESError.invalidSeed` if the seed is not 32 bytes.
    public static func split(seed: Data) throws -> (left: Data, right: Data) {
        guard seed.count == KESConstants.seedSize else {
            throw KESError.invalidSeed
        }

        let sodium = Sodium()

        // Domain separator 0x01 prepended to seed for the left child
        let leftInput = Data([0x01]) + seed
        let left = try sodium.cryptoGenericHash.blake2bSaltPersonal(
            data: leftInput,
            digestSize: KESConstants.seedSize
        )

        // Domain separator 0x02 prepended to seed for the right child
        let rightInput = Data([0x02]) + seed
        let right = try sodium.cryptoGenericHash.blake2bSaltPersonal(
            data: rightInput,
            digestSize: KESConstants.seedSize
        )

        return (left, right)
    }
}
