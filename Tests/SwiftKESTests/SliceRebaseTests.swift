import Foundation
import Testing
@testable import SwiftKES

/// Regression tests for byte buffers passed as non-zero-based `Data` slices
/// (e.g. `data[3...]` after stripping a CBOR header).
struct SliceRebaseTests {

    private let seed = Data(repeating: 0x42, count: 32)
    private let message = Data("slice regression".utf8)

    private func slice(of bytes: Data, offset: Int) -> Data {
        let backing = Data(repeating: 0xEE, count: offset) + bytes
        let sliced = backing[offset...]
        precondition(sliced.startIndex == offset)
        return sliced
    }

    // MARK: - Secret key restore

    @Test(arguments: [1, 3, 31, 32, 33, 64, 65, 200])
    func standardKeyRestoredFromSliceMatchesFreshKey(offset: Int) throws {
        var fresh = try Sum6KES(seed: seed)
        var restored = try Sum6KES(secretKeyBytes: slice(of: fresh.secretKeyBytes, offset: offset), period: 0)

        #expect(restored.secretKeyBytes.startIndex == 0)
        #expect(restored.publicKey == fresh.publicKey)

        for period in [0, 1, 31, 32, 63] as [UInt] {
            while fresh.currentPeriod < period {
                try fresh.evolve()
                try restored.evolve()
            }
            let sig = try restored.sign(message: message)
            #expect(sig == (try fresh.sign(message: message)))
            #expect(try Sum6KES.verify(publicKey: fresh.publicKey, period: period, signature: sig, message: message))
            #expect(restored.secretKeyBytes == fresh.secretKeyBytes)
        }
    }

    @Test(arguments: [1, 3, 32, 64, 65, 200])
    func compactKeyRestoredFromSliceMatchesFreshKey(offset: Int) throws {
        var fresh = try Sum6CompactKES(seed: seed)
        var restored = try Sum6CompactKES(secretKeyBytes: slice(of: fresh.secretKeyBytes, offset: offset), period: 0)

        #expect(restored.publicKey == fresh.publicKey)

        for period in [0, 1, 32, 63] as [UInt] {
            while fresh.currentPeriod < period {
                try fresh.evolve()
                try restored.evolve()
            }
            let sig = try restored.sign(message: message)
            #expect(sig == (try fresh.sign(message: message)))
            #expect(try Sum6CompactKES.verify(publicKey: fresh.publicKey, period: period, signature: sig, message: message))
        }
    }

    @Test func signatureFromSliceRestoredKeyLeaksNoSeedBytes() throws {
        let fresh = try Sum6KES(seed: seed)
        let raw = fresh.secretKeyBytes
        let restored = try Sum6KES(secretKeyBytes: slice(of: raw, offset: 32), period: 0)
        let sig = try restored.sign(message: message)

        // Top-level stored seed lives at raw[512..<544]; it must never appear in a signature.
        let topSeed = raw[512..<544]
        #expect(sig.bytes.range(of: topSeed) == nil)
    }

    // MARK: - Signature verification

    @Test(arguments: [1, 100, 384, 385, 500])
    func standardSignatureFromSliceVerifies(offset: Int) throws {
        var kes = try Sum6KES(seed: seed)
        for _ in 0..<37 { try kes.evolve() }
        let sig = try kes.sign(message: message)

        let sliced = try KESSignature(depth: Sum6KES.depth, bytes: slice(of: sig.bytes, offset: offset))
        #expect(sliced == sig)
        #expect(try Sum6KES.verify(publicKey: kes.publicKey, period: 37, signature: sliced, message: message))
    }

    @Test(arguments: [1, 100, 256, 257, 300])
    func compactSignatureFromSliceVerifies(offset: Int) throws {
        var kes = try Sum6CompactKES(seed: seed)
        for _ in 0..<37 { try kes.evolve() }
        let sig = try kes.sign(message: message)

        let sliced = try KESCompactSignature(depth: Sum6CompactKES.depth, bytes: slice(of: sig.bytes, offset: offset))
        #expect(sliced == sig)
        #expect(try Sum6CompactKES.verify(publicKey: kes.publicKey, period: 37, signature: sliced, message: message))
    }

    @Test func publicKeyFromSliceIsRebased() throws {
        let kes = try Sum6KES(seed: seed)
        let pk = try KESPublicKey(bytes: slice(of: kes.publicKey.bytes, offset: 7))
        #expect(pk.bytes.startIndex == 0)
        #expect(pk == kes.publicKey)
    }
}
