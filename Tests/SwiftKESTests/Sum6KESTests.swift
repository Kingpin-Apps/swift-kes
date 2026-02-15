import Foundation
import Testing
@testable import SwiftKES

/// High-level Sum6KES and Sum6CompactKES integration tests.
struct Sum6KESTests {

    // MARK: - Sum6KES Standard

    @Test func sum6KESGenerateAndSign() throws {
        let seed = Data(repeating: 0xAA, count: 32)
        let kes = try Sum6KES(seed: seed)

        #expect(kes.currentPeriod == 0)
        #expect(kes.publicKey.bytes.count == 32)
        #expect(kes.secretKeyBytes.count == 608)

        let message = Data("hello cardano".utf8)
        let sig = try kes.sign(message: message)
        #expect(sig.bytes.count == 448)

        let valid = try Sum6KES.verify(
            publicKey: kes.publicKey,
            period: 0,
            signature: sig,
            message: message
        )
        #expect(valid)
    }

    @Test func sum6KESEvolveAndVerify() throws {
        let seed = Data(repeating: 0xBB, count: 32)
        var kes = try Sum6KES(seed: seed)
        let pk = kes.publicKey
        let message = Data("evolve test".utf8)

        // Sign at period 0
        let sig0 = try kes.sign(message: message)
        #expect(try Sum6KES.verify(publicKey: pk, period: 0, signature: sig0, message: message))

        // Evolve to period 1
        try kes.evolve()
        #expect(kes.currentPeriod == 1)

        // Sign at period 1
        let sig1 = try kes.sign(message: message)
        #expect(try Sum6KES.verify(publicKey: pk, period: 1, signature: sig1, message: message))

        // Old signature still verifies (it's self-contained)
        #expect(try Sum6KES.verify(publicKey: pk, period: 0, signature: sig0, message: message))
    }

    @Test func sum6KESFullLifecycle() throws {
        let seed = Data(repeating: 0xCC, count: 32)
        var kes = try Sum6KES(seed: seed)
        let pk = kes.publicKey
        let message = Data("full lifecycle".utf8)

        // Sign and verify at every period
        for period: UInt in 0 ..< 64 {
            #expect(kes.currentPeriod == period)

            let sig = try kes.sign(message: message)
            let valid = try Sum6KES.verify(
                publicKey: pk,
                period: period,
                signature: sig,
                message: message
            )
            #expect(valid, "Failed at period \(period)")

            if period < 63 {
                try kes.evolve()
            }
        }

        // Exhausted — cannot evolve past period 63
        #expect(kes.currentPeriod == 63)
        #expect(throws: KESError.keyExhausted) {
            try kes.evolve()
        }
    }

    @Test func sum6KESDifferentMessagesProduceDifferentSignatures() throws {
        let seed = Data(repeating: 0xDD, count: 32)
        let kes = try Sum6KES(seed: seed)

        let sig1 = try kes.sign(message: Data("message 1".utf8))
        let sig2 = try kes.sign(message: Data("message 2".utf8))

        #expect(sig1.bytes != sig2.bytes)
    }

    @Test func sum6KESSerializationRoundTrip() throws {
        let seed = Data(repeating: 0xEE, count: 32)
        var kes1 = try Sum6KES(seed: seed)
        let message = Data("serialize test".utf8)

        // Evolve a few times
        try kes1.evolve()
        try kes1.evolve()
        try kes1.evolve()
        #expect(kes1.currentPeriod == 3)

        // Serialize and restore
        let skBytes = kes1.secretKeyBytes
        let kes2 = try Sum6KES(secretKeyBytes: skBytes, period: 3)

        // Both should produce the same signature
        let sig1 = try kes1.sign(message: message)
        let sig2 = try kes2.sign(message: message)
        #expect(sig1.bytes == sig2.bytes)

        // Both have the same public key
        #expect(kes1.publicKey == kes2.publicKey)
    }

    // MARK: - Sum6CompactKES

    @Test func sum6CompactKESGenerateAndSign() throws {
        let seed = Data(repeating: 0x11, count: 32)
        let kes = try Sum6CompactKES(seed: seed)

        #expect(kes.currentPeriod == 0)
        #expect(kes.publicKey.bytes.count == 32)
        #expect(kes.secretKeyBytes.count == 608)

        let message = Data("compact hello".utf8)
        let sig = try kes.sign(message: message)
        #expect(sig.bytes.count == 288)

        let valid = try Sum6CompactKES.verify(
            publicKey: kes.publicKey,
            period: 0,
            signature: sig,
            message: message
        )
        #expect(valid)
    }

    @Test func sum6CompactKESFullLifecycle() throws {
        let seed = Data(repeating: 0x22, count: 32)
        var kes = try Sum6CompactKES(seed: seed)
        let pk = kes.publicKey
        let message = Data("compact lifecycle".utf8)

        for period: UInt in 0 ..< 64 {
            #expect(kes.currentPeriod == period)

            let sig = try kes.sign(message: message)
            let valid = try Sum6CompactKES.verify(
                publicKey: pk,
                period: period,
                signature: sig,
                message: message
            )
            #expect(valid, "Compact failed at period \(period)")

            if period < 63 {
                try kes.evolve()
            }
        }

        #expect(throws: KESError.keyExhausted) {
            try kes.evolve()
        }
    }

    @Test func sum6CompactKESSerializationRoundTrip() throws {
        let seed = Data(repeating: 0x33, count: 32)
        var kes1 = try Sum6CompactKES(seed: seed)

        try kes1.evolve()
        try kes1.evolve()

        let skBytes = kes1.secretKeyBytes
        let kes2 = try Sum6CompactKES(secretKeyBytes: skBytes, period: 2)

        let message = Data("compact serialize".utf8)
        let sig1 = try kes1.sign(message: message)
        let sig2 = try kes2.sign(message: message)
        #expect(sig1.bytes == sig2.bytes)
        #expect(kes1.publicKey == kes2.publicKey)
    }

    // MARK: - Cross-variant consistency

    @Test func standardAndCompactShareSameKeys() throws {
        let seed = Data(repeating: 0x44, count: 32)
        let standard = try Sum6KES(seed: seed)
        let compact = try Sum6CompactKES(seed: seed)

        // Same seed → same public key
        #expect(standard.publicKey == compact.publicKey)
        // Same seed → same secret key bytes
        #expect(standard.secretKeyBytes == compact.secretKeyBytes)
    }
}
