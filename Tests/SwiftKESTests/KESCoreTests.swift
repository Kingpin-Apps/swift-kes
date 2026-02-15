import Foundation
import Testing
@testable import SwiftKES

/// Core algorithm tests for KES key generation, signing, verification,
/// key evolution, and compact variants.
struct KESCoreTests {

    // MARK: - Seed Splitting

    @Test func seedSplittingIsDeterministic() throws {
        let seed = Data(repeating: 0xAB, count: 32)
        let (left1, right1) = try SeedSplitter.split(seed: seed)
        let (left2, right2) = try SeedSplitter.split(seed: seed)
        #expect(left1 == left2)
        #expect(right1 == right2)
    }

    @Test func seedSplittingProducesDifferentOutputs() throws {
        let seed = Data(repeating: 0xCD, count: 32)
        let (left, right) = try SeedSplitter.split(seed: seed)
        #expect(left != right)
        #expect(left.count == 32)
        #expect(right.count == 32)
    }

    @Test func seedSplittingRejectsInvalidSize() throws {
        let badSeed = Data(repeating: 0, count: 16)
        #expect(throws: KESError.invalidSeed) {
            _ = try SeedSplitter.split(seed: badSeed)
        }
    }

    // MARK: - Hash Pair

    @Test func hashPairIsDeterministic() throws {
        let a = Data(repeating: 0x11, count: 32)
        let b = Data(repeating: 0x22, count: 32)
        let h1 = try HashPair.combine(a, b)
        let h2 = try HashPair.combine(a, b)
        #expect(h1 == h2)
        #expect(h1.count == 32)
    }

    @Test func hashPairIsOrderDependent() throws {
        let a = Data(repeating: 0x11, count: 32)
        let b = Data(repeating: 0x22, count: 32)
        let h1 = try HashPair.combine(a, b)
        let h2 = try HashPair.combine(b, a)
        #expect(h1 != h2)
    }

    // MARK: - Key Generation Size Tests

    @Test func keygenDepth0ProducesCorrectSizes() throws {
        let seed = Data(repeating: 0x01, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 0, seed: seed)
        #expect(sk.bytes.count == 32)
        #expect(pk.bytes.count == 32)
    }

    @Test func keygenDepth1ProducesCorrectSizes() throws {
        let seed = Data(repeating: 0x02, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 1, seed: seed)
        #expect(sk.bytes.count == 128)
        #expect(pk.bytes.count == 32)
    }

    @Test func keygenDepth2ProducesCorrectSizes() throws {
        let seed = Data(repeating: 0x03, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 2, seed: seed)
        #expect(sk.bytes.count == 224)
        #expect(pk.bytes.count == 32)
    }

    @Test func keygenDepth6ProducesCorrectSizes() throws {
        let seed = Data(repeating: 0x04, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 6, seed: seed)
        #expect(sk.bytes.count == 608)
        #expect(pk.bytes.count == 32)
    }

    @Test func keygenIsDeterministic() throws {
        let seed = Data(repeating: 0x05, count: 32)
        let (sk1, pk1) = try KESCore.keygen(depth: 3, seed: seed)
        let (sk2, pk2) = try KESCore.keygen(depth: 3, seed: seed)
        #expect(sk1.bytes == sk2.bytes)
        #expect(pk1.bytes == pk2.bytes)
    }

    @Test func differentSeedsProduceDifferentKeys() throws {
        let seed1 = Data(repeating: 0x06, count: 32)
        let seed2 = Data(repeating: 0x07, count: 32)
        let (_, pk1) = try KESCore.keygen(depth: 3, seed: seed1)
        let (_, pk2) = try KESCore.keygen(depth: 3, seed: seed2)
        #expect(pk1.bytes != pk2.bytes)
    }

    // MARK: - Standard Sign + Verify Round Trip

    @Test func signVerifyDepth0() throws {
        let seed = Data(repeating: 0x10, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 0, seed: seed)
        let message = Data("test message".utf8)

        let sig = try KESCore.sign(depth: 0, sk: sk, period: 0, message: message)
        #expect(sig.bytes.count == 64)

        let valid = try KESCore.verify(depth: 0, pk: pk, period: 0, signature: sig, message: message)
        #expect(valid)
    }

    @Test func signVerifyDepth1AllPeriods() throws {
        let seed = Data(repeating: 0x11, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 1, seed: seed)
        let message = Data("depth1 test".utf8)

        // Period 0
        let sig0 = try KESCore.sign(depth: 1, sk: sk, period: 0, message: message)
        #expect(sig0.bytes.count == 128)
        #expect(try KESCore.verify(depth: 1, pk: pk, period: 0, signature: sig0, message: message))

        // Evolve to period 1
        try KESCore.update(depth: 1, sk: sk, currentPeriod: 0)

        let sig1 = try KESCore.sign(depth: 1, sk: sk, period: 1, message: message)
        #expect(try KESCore.verify(depth: 1, pk: pk, period: 1, signature: sig1, message: message))
    }

    @Test func signVerifyDepth4AllPeriods() throws {
        let seed = Data(repeating: 0x14, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 4, seed: seed)
        let message = Data("depth4 exhaustive".utf8)

        let totalPeriods = KESConstants.totalPeriods(depth: 4) // 16
        for period in 0 ..< totalPeriods {
            let sig = try KESCore.sign(depth: 4, sk: sk, period: UInt(period), message: message)
            let valid = try KESCore.verify(depth: 4, pk: pk, period: UInt(period), signature: sig, message: message)
            #expect(valid, "Verification failed at period \(period)")

            if period + 1 < totalPeriods {
                try KESCore.update(depth: 4, sk: sk, currentPeriod: UInt(period))
            }
        }
    }

    // MARK: - Key Evolution

    @Test func updateDepth0ThrowsExhausted() throws {
        let seed = Data(repeating: 0x20, count: 32)
        let (sk, _) = try KESCore.keygen(depth: 0, seed: seed)
        #expect(throws: KESError.keyExhausted) {
            try KESCore.update(depth: 0, sk: sk, currentPeriod: 0)
        }
    }

    @Test func updateDepth1TransitionsCorrectly() throws {
        let seed = Data(repeating: 0x21, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 1, seed: seed)
        let message = Data("evolve test".utf8)

        // Sign at period 0
        let sig0 = try KESCore.sign(depth: 1, sk: sk, period: 0, message: message)
        #expect(try KESCore.verify(depth: 1, pk: pk, period: 0, signature: sig0, message: message))

        // Evolve: period 0 → period 1 (this crosses the midpoint, expanding right subtree)
        try KESCore.update(depth: 1, sk: sk, currentPeriod: 0)

        // Sign at period 1
        let sig1 = try KESCore.sign(depth: 1, sk: sk, period: 1, message: message)
        #expect(try KESCore.verify(depth: 1, pk: pk, period: 1, signature: sig1, message: message))

        // Exhausted
        #expect(throws: KESError.keyExhausted) {
            try KESCore.update(depth: 1, sk: sk, currentPeriod: 1)
        }
    }

    // MARK: - Forward Security

    @Test func forwardSecurityAfterEvolution() throws {
        let seed = Data(repeating: 0x30, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 2, seed: seed)
        let message = Data("forward security".utf8)

        // Sign at period 0
        let sig0 = try KESCore.sign(depth: 2, sk: sk, period: 0, message: message)
        #expect(try KESCore.verify(depth: 2, pk: pk, period: 0, signature: sig0, message: message))

        // Evolve to period 1
        try KESCore.update(depth: 2, sk: sk, currentPeriod: 0)

        // Old signature at period 0 should still verify (the sig itself is independent)
        #expect(try KESCore.verify(depth: 2, pk: pk, period: 0, signature: sig0, message: message))

        // But the key at period 0 is gone — we can only sign at period 1 now
        let sig1 = try KESCore.sign(depth: 2, sk: sk, period: 1, message: message)
        #expect(try KESCore.verify(depth: 2, pk: pk, period: 1, signature: sig1, message: message))
    }

    // MARK: - Invalid Signature Detection

    @Test func invalidSignatureRejected() throws {
        let seed = Data(repeating: 0x40, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 1, seed: seed)
        let message = Data("valid message".utf8)

        let sig = try KESCore.sign(depth: 1, sk: sk, period: 0, message: message)

        // Tamper with the signature
        var tampered = sig.bytes
        tampered[0] ^= 0xFF
        let tamperedSig = try KESSignature(depth: 1, bytes: tampered)

        let valid = try KESCore.verify(depth: 1, pk: pk, period: 0, signature: tamperedSig, message: message)
        #expect(!valid)
    }

    @Test func wrongMessageRejected() throws {
        let seed = Data(repeating: 0x41, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 1, seed: seed)

        let sig = try KESCore.sign(depth: 1, sk: sk, period: 0, message: Data("correct".utf8))
        let valid = try KESCore.verify(depth: 1, pk: pk, period: 0, signature: sig, message: Data("wrong".utf8))
        #expect(!valid)
    }

    @Test func wrongPeriodRejected() throws {
        let seed = Data(repeating: 0x42, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 2, seed: seed)
        let message = Data("period test".utf8)

        let sig = try KESCore.sign(depth: 2, sk: sk, period: 0, message: message)

        // Verify with the wrong period
        let valid = try KESCore.verify(depth: 2, pk: pk, period: 1, signature: sig, message: message)
        #expect(!valid)
    }

    @Test func periodOutOfRangeRejected() throws {
        let seed = Data(repeating: 0x43, count: 32)
        let (_, pk) = try KESCore.keygen(depth: 1, seed: seed)

        // Period 2 is out of range for depth 1 (max = 2)
        let dummySig = try KESSignature(depth: 1, bytes: Data(repeating: 0, count: 128))
        let valid = try KESCore.verify(depth: 1, pk: pk, period: 2, signature: dummySig, message: Data())
        #expect(!valid)
    }

    // MARK: - Compact Sign + Verify

    @Test func compactSignVerifyDepth0() throws {
        let seed = Data(repeating: 0x50, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 0, seed: seed)
        let message = Data("compact depth0".utf8)

        let sig = try KESCore.signCompact(depth: 0, sk: sk, period: 0, message: message)
        #expect(sig.bytes.count == 96) // 64 sig + 32 pk

        let valid = try KESCore.verifyCompact(depth: 0, pk: pk, period: 0, signature: sig, message: message)
        #expect(valid)
    }

    @Test func compactSignVerifyDepth1() throws {
        let seed = Data(repeating: 0x51, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 1, seed: seed)
        let message = Data("compact depth1".utf8)

        // Period 0
        let sig0 = try KESCore.signCompact(depth: 1, sk: sk, period: 0, message: message)
        #expect(sig0.bytes.count == KESConstants.compactSignatureSize(depth: 1))
        #expect(try KESCore.verifyCompact(depth: 1, pk: pk, period: 0, signature: sig0, message: message))

        // Evolve and test period 1
        try KESCore.update(depth: 1, sk: sk, currentPeriod: 0)
        let sig1 = try KESCore.signCompact(depth: 1, sk: sk, period: 1, message: message)
        #expect(try KESCore.verifyCompact(depth: 1, pk: pk, period: 1, signature: sig1, message: message))
    }

    @Test func compactSignVerifyDepth4AllPeriods() throws {
        let seed = Data(repeating: 0x54, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 4, seed: seed)
        let message = Data("compact depth4".utf8)

        let total = KESConstants.totalPeriods(depth: 4) // 16
        for period in 0 ..< total {
            let sig = try KESCore.signCompact(depth: 4, sk: sk, period: UInt(period), message: message)
            let valid = try KESCore.verifyCompact(depth: 4, pk: pk, period: UInt(period), signature: sig, message: message)
            #expect(valid, "Compact verification failed at period \(period)")

            if period + 1 < total {
                try KESCore.update(depth: 4, sk: sk, currentPeriod: UInt(period))
            }
        }
    }

    @Test func compactInvalidSignatureRejected() throws {
        let seed = Data(repeating: 0x55, count: 32)
        let (sk, pk) = try KESCore.keygen(depth: 1, seed: seed)
        let message = Data("compact tamper".utf8)

        let sig = try KESCore.signCompact(depth: 1, sk: sk, period: 0, message: message)

        var tampered = sig.bytes
        tampered[0] ^= 0xFF
        let tamperedSig = try KESCompactSignature(depth: 1, bytes: tampered)

        let valid = try KESCore.verifyCompact(depth: 1, pk: pk, period: 0, signature: tamperedSig, message: message)
        #expect(!valid)
    }

    // MARK: - Constants Validation

    @Test func constantsSizesAreCorrect() {
        // Secret key sizes
        #expect(KESConstants.secretKeySize(depth: 0) == 32)
        #expect(KESConstants.secretKeySize(depth: 1) == 128)
        #expect(KESConstants.secretKeySize(depth: 2) == 224)
        #expect(KESConstants.secretKeySize(depth: 3) == 320)
        #expect(KESConstants.secretKeySize(depth: 4) == 416)
        #expect(KESConstants.secretKeySize(depth: 5) == 512)
        #expect(KESConstants.secretKeySize(depth: 6) == 608)

        // Standard signature sizes
        #expect(KESConstants.signatureSize(depth: 0) == 64)
        #expect(KESConstants.signatureSize(depth: 1) == 128)
        #expect(KESConstants.signatureSize(depth: 6) == 448)

        // Compact signature sizes
        #expect(KESConstants.compactSignatureSize(depth: 0) == 96)
        #expect(KESConstants.compactSignatureSize(depth: 1) == 128)
        #expect(KESConstants.compactSignatureSize(depth: 6) == 288)

        // Total periods
        #expect(KESConstants.totalPeriods(depth: 0) == 1)
        #expect(KESConstants.totalPeriods(depth: 1) == 2)
        #expect(KESConstants.totalPeriods(depth: 6) == 64)
    }
}
