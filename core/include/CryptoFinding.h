#pragma once
#include <string>
#include <vector>

namespace ecdat {

// Risk level of a finding
enum class RiskLevel { SAFE, MODERATE, CRITICAL };

// What kind of cryptographic asset was found
enum class FindingType {
    ALGORITHM_USAGE,   // e.g. RSA call in source code
    KEY_MATERIAL,      // hardcoded key or certificate
    PROTOCOL_CONFIG,   // TLS version in config
    LIBRARY_IMPORT,    // import of weak crypto library
    BINARY_SIGNATURE   // YARA / Capstone match in binary
};

// How quantum computers threaten this algorithm
enum class QuantumThreat {
    BROKEN_BY_SHORS,    // RSA, ECC, DH — completely broken
    WEAKENED_BY_GROVERS,// AES-128, SHA-1, MD5 — key strength halved
    QUANTUM_SAFE,       // AES-256, SHA-512 — still safe
    UNKNOWN
};

// One discovered cryptographic asset with Multi-Stage Confidence & Mosca Theorem metrics
struct CryptoFinding {
    std::string   id;               // unique ID for this finding
    FindingType   type  = FindingType::ALGORITHM_USAGE;

    // Where it was found
    std::string   filePath;
    int           lineNumber = 0;

    // What was found
    std::string   algorithmName;    // "RSA", "AES-128-CBC", "MD5"
    std::string   algorithmFamily;  // "Asymmetric", "Symmetric", "Hash"
    int           keyLength  = 0;   // bits; 0 = unknown

    // Risk
    RiskLevel     riskLevel  = RiskLevel::MODERATE;
    QuantumThreat quantumThreat = QuantumThreat::UNKNOWN;
    std::string   cweId;            // "CWE-327"

    // Recommendation
    std::string   pqcReplacement;   // "ML-KEM-768 (Kyber)"
    std::string   migrationNote;

    // Multi-Stage Detection & Confidence (100% for AST & YARA, ML-derived % for Inference)
    std::string   confidence = "100.0%"; // "100.0%", "42.0%", "89.5%"
    std::string   matchedSnippet;        // Evidence snippet or signature match
    std::string   scannerSource = "AST Parser"; // "AST Parser", "YARA Scanner", "ML Inference"

    // ── Mosca's Theorem Per-Asset Prioritization ────────────────
    double      moscaX = 15.0;            // Data Secrecy Horizon (years)
    double      moscaY = 3.0;             // Refactoring / Migration timeline (years)
    double      quantumMargin = -8.0;     // Z - (X + Y) margin (negative = deficit / HNDL active)
    int         urgencyRank = 1;          // 1 = Fix First / Immediate, 2 = High, 3 = Moderate, 4 = Safe
    std::string fixUrgency = "IMMEDIATE"; // "IMMEDIATE", "HIGH", "MODERATE", "SAFE"
    std::string fixDeadline = "Fix TODAY (HNDL Active)";
};

using FindingList = std::vector<CryptoFinding>;

} // namespace ecdat
