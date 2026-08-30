#pragma once

#include <string>
#include <vector>
#include <optional>

namespace ecdat {

enum class AssetType {
    Symmetric,
    Asymmetric,
    Hash,
    Protocol,
    Unknown,
};

enum class Severity {
    Critical, // RSA, ECC, MD5, DES (Broken by Quantum or classical attacks)
    Moderate, // AES-128, 3DES (Weakened by Grover's algorithm)
    Safe,     // AES-256, SHA-256, PQC (Quantum Resistant)
};

enum SourceStage {
    AST_Parser,             // Stage 1: Static AST Source Code Analysis
    YARA_Scanner,           // Stage 2: Binary Byte Signature & S-Box Matching
    Heuristic_Inference,    // Stage 3: Blind Statistical & ML Ciphertext Inference
};

struct CryptoOccurrence {
    int lineNumber;
    std::string snippet;
};

struct CryptoAsset {
    std::string filePath;
    std::optional<int> lineNumber;
    AssetType type;
    std::string algorithm;
    std::optional<int> keySize;
    std::optional<std::string> mode;
    Severity severity;
    std::string confidence;
    SourceStage stage;
    std::string evidence;
    std::vector<CryptoOccurrence> allOccurrences;

    std::string severityString() const {
        switch (severity) {
            case Severity::Critical:
                return "CRITICAL (Quantum Broken / Insecure)";
            case Severity::Moderate:
                return "MODERATE (Quantum Weakened)";
            case Severity::Safe:
                return "SAFE (Quantum Resistant)";
        }
        return "UNKNOWN";
    }

    std::string typeString() const {
        switch (type) {
            case AssetType::Symmetric:
                return "Symmetric Cipher";
            case AssetType::Asymmetric:
                return "Asymmetric Key / Signature";
            case AssetType::Hash:
                return "Hash Function";
            case AssetType::Protocol:
                return "Protocol / Library";
            default:
                return "Unknown";
        }
    }

    std::string remediationAdvice() const {
        if (algorithm.find("RSA") != std::string::npos) {
            if (keySize.has_value() && keySize.value() <= 1024) {
                return "URGENT VULNERABILITY: 1024-bit RSA is classically factorable and quantum broken. Upgrade immediately to NIST FIPS 203 (ML-KEM-768).";
            }
            return "MIGRATE TO NIST FIPS 203 (ML-KEM-768 / Kyber) for key encapsulation, or ML-DSA (Dilithium) for signatures.";
        } else if (algorithm.find("ECC") != std::string::npos || algorithm.find("P-256") != std::string::npos) {
            return "MIGRATE TO NIST FIPS 204 (ML-DSA / Dilithium) or SLH-DSA (SPHINCS+).";
        } else if (algorithm == "MD5" || algorithm == "SHA-1") {
            return "UPGRADE TO SHA-256 or SHA-3 (FIPS 202). MD5/SHA-1 are vulnerable to collision attacks.";
        } else if (algorithm == "3DES" || algorithm == "DES" || algorithm == "Blowfish" || algorithm == "RC4") {
            return "DEPRECATE IMMEDIATELY. Replace with AES-256-GCM or ChaCha20-Poly1305.";
        } else if (algorithm == "AES-128") {
            return "UPGRADE KEY SIZE to AES-256 to ensure 128 bits of post-quantum security against Grover's algorithm.";
        } else if (algorithm == "AES-256" || algorithm == "SHA-256" || algorithm == "SHA-512" || algorithm.find("ChaCha20") != std::string::npos) {
            return "NO ACTION REQUIRED. Algorithm meets NIST Post-Quantum standards.";
        }
        return "AUDIT IMPLEMENTATION against NIST SP 800-131A guidelines.";
    }
};

} // namespace ecdat
