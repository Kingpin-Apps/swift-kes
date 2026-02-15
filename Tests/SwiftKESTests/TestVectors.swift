import Foundation
import Testing
@testable import SwiftKES

/// Binary test vector validation against the Rust `input-output-hk/kes` crate.
///
/// Test vectors are generated with:
/// - Seed: `"test string of 32 byte of lenght"` (32 ASCII bytes — note the typo is intentional)
/// - Message: `"test message"` (12 ASCII bytes)
///
/// The .bin files in Resources/ are downloaded from:
/// https://github.com/input-output-hk/kes/tree/master/tests/data
///
/// The binary files store the raw SK bytes (without appended period) and
/// raw signature bytes, matching our implementation's output format.
struct TestVectors {

    /// The canonical test seed used by the Rust test suite.
    static let testSeed = Data("test string of 32 byte of lenght".utf8)

    /// The canonical test message.
    static let testMessage = Data("test message".utf8)

    /// Load a binary test vector file from the Resources bundle.
    private static func loadVector(_ filename: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: filename, withExtension: nil, subdirectory: "Resources") else {
            throw KESError.internalError("Test vector file not found: \(filename)")
        }
        return try Data(contentsOf: url)
    }

    // MARK: - Standard Key Generation

    @Test func standardKey0MatchesVector() throws {
        let vector = try Self.loadVector("key0.bin")
        let (sk, _) = try KESCore.keygen(depth: 0, seed: Self.testSeed)

        #expect(sk.bytes == vector, "Depth 0 SK mismatch (expected \(vector.count) bytes, got \(sk.bytes.count))")
    }

    @Test func standardKey1MatchesVector() throws {
        let vector = try Self.loadVector("key1.bin")
        let (sk, _) = try KESCore.keygen(depth: 1, seed: Self.testSeed)

        #expect(sk.bytes == vector, "Depth 1 SK mismatch (expected \(vector.count) bytes, got \(sk.bytes.count))")
    }

    @Test func standardKey6MatchesVector() throws {
        let vector = try Self.loadVector("key6.bin")
        let (sk, _) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        #expect(sk.bytes == vector, "Depth 6 SK mismatch (expected \(vector.count) bytes, got \(sk.bytes.count))")
    }

    // MARK: - Standard Key After Evolution

    @Test func standardKey6Update1MatchesVector() throws {
        let vector = try Self.loadVector("key6update1.bin")
        let (sk, _) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        // Evolve once (period 0 → 1)
        try KESCore.update(depth: 6, sk: sk, currentPeriod: 0)

        #expect(sk.bytes == vector, "Depth 6 SK after 1 update mismatch")
    }

    @Test func standardKey6Update5MatchesVector() throws {
        let vector = try Self.loadVector("key6update5.bin")
        let (sk, _) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        // Evolve 5 times (period 0 → 5)
        for period: UInt in 0 ..< 5 {
            try KESCore.update(depth: 6, sk: sk, currentPeriod: period)
        }

        #expect(sk.bytes == vector, "Depth 6 SK after 5 updates mismatch")
    }

    // MARK: - Standard Signatures

    @Test func standardSig6Period0MatchesVector() throws {
        let vector = try Self.loadVector("key6Sig.bin")
        let (sk, pk) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        let sig = try KESCore.sign(depth: 6, sk: sk, period: 0, message: Self.testMessage)
        #expect(sig.bytes == vector, "Depth 6 signature at period 0 mismatch")

        // Also verify the vector signature
        let vecSig = try KESSignature(depth: 6, bytes: vector)
        #expect(try KESCore.verify(depth: 6, pk: pk, period: 0, signature: vecSig, message: Self.testMessage))
    }

    @Test func standardSig6Period5MatchesVector() throws {
        let vector = try Self.loadVector("key6Sig5.bin")
        let (sk, pk) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        // Evolve to period 5
        for period: UInt in 0 ..< 5 {
            try KESCore.update(depth: 6, sk: sk, currentPeriod: period)
        }

        let sig = try KESCore.sign(depth: 6, sk: sk, period: 5, message: Self.testMessage)
        #expect(sig.bytes == vector, "Depth 6 signature at period 5 mismatch")

        // Verify the vector signature
        let vecSig = try KESSignature(depth: 6, bytes: vector)
        #expect(try KESCore.verify(depth: 6, pk: pk, period: 5, signature: vecSig, message: Self.testMessage))
    }

    // MARK: - Compact Key Generation

    @Test func compactKey0MatchesVector() throws {
        let vector = try Self.loadVector("compactkey0.bin")
        let (sk, _) = try KESCore.keygen(depth: 0, seed: Self.testSeed)

        // Compact and standard use the same keygen — same SK bytes
        #expect(sk.bytes == vector, "Compact depth 0 SK mismatch")
    }

    @Test func compactKey1MatchesVector() throws {
        let vector = try Self.loadVector("compactkey1.bin")
        let (sk, _) = try KESCore.keygen(depth: 1, seed: Self.testSeed)

        #expect(sk.bytes == vector, "Compact depth 1 SK mismatch")
    }

    @Test func compactKey6MatchesVector() throws {
        let vector = try Self.loadVector("compactkey6.bin")
        let (sk, _) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        #expect(sk.bytes == vector, "Compact depth 6 SK mismatch")
    }

    // MARK: - Compact Key After Evolution

    @Test func compactKey6Update1MatchesVector() throws {
        let vector = try Self.loadVector("compactkey6update1.bin")
        let (sk, _) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        try KESCore.update(depth: 6, sk: sk, currentPeriod: 0)

        #expect(sk.bytes == vector, "Compact depth 6 SK after 1 update mismatch")
    }

    @Test func compactKey6Update5MatchesVector() throws {
        let vector = try Self.loadVector("compactkey6update5.bin")
        let (sk, _) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        for period: UInt in 0 ..< 5 {
            try KESCore.update(depth: 6, sk: sk, currentPeriod: period)
        }

        #expect(sk.bytes == vector, "Compact depth 6 SK after 5 updates mismatch")
    }

    // MARK: - Compact Signatures

    @Test func compactSig6Period0MatchesVector() throws {
        let vector = try Self.loadVector("compactkey6Sig.bin")
        let (sk, pk) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        let sig = try KESCore.signCompact(depth: 6, sk: sk, period: 0, message: Self.testMessage)
        #expect(sig.bytes == vector, "Compact depth 6 signature at period 0 mismatch")

        // Verify the vector signature
        let vecSig = try KESCompactSignature(depth: 6, bytes: vector)
        #expect(try KESCore.verifyCompact(depth: 6, pk: pk, period: 0, signature: vecSig, message: Self.testMessage))
    }

    @Test func compactSig6Period5MatchesVector() throws {
        let vector = try Self.loadVector("compactkey6Sig5.bin")
        let (sk, pk) = try KESCore.keygen(depth: 6, seed: Self.testSeed)

        for period: UInt in 0 ..< 5 {
            try KESCore.update(depth: 6, sk: sk, currentPeriod: period)
        }

        let sig = try KESCore.signCompact(depth: 6, sk: sk, period: 5, message: Self.testMessage)
        #expect(sig.bytes == vector, "Compact depth 6 signature at period 5 mismatch")

        // Verify the vector signature
        let vecSig = try KESCompactSignature(depth: 6, bytes: vector)
        #expect(try KESCore.verifyCompact(depth: 6, pk: pk, period: 5, signature: vecSig, message: Self.testMessage))
    }
}
