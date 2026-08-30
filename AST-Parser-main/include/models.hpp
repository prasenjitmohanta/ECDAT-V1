#pragma once

#include <string>
#include <optional>

using namespace std;

namespace ecdat {

enum class AssetType{
    Symmetric,
    Asymmetric,
    Hash,
    Protocol,
    Unknown,
};

enum class Severity{
    Critical, // RSA, ECC, MD5, DES (Broken by Quantum or classical attacks)
    Moderate, // AES-128, 3DES (Weakend by grovers algorthm)
    Safe, // AES-256, SHA-256, PQC (Quantum Resistant)
};

enum SourceStage{
    AST_Parser,
    YARA_Scanner,
    ML_Triage,
};

struct CryptoAsset{
    string filePath;
    optional<int> lineNumber;
    AssetType type;
    string algorithm; // Tells the algorithm
    optional<int> keySize; // 128 or 256
    optional<string>mode; // CBC/GCM/ECB
    Severity severity;
    string confidence;
    SourceStage stage;
    string evidence;

    string severityString() const {
        switch (severity) {
            case ecdat::Severity::Critical:
                return "CRITICAL (Quantum Broken / Insecure)";
            case ecdat::Severity::Moderate:
                return "MODERATE (Quantum Weakened)";
            case ecdat::Severity::Safe:
                return "SAFE (Quantum Resistant)";
        }

        return "UNKNOWN";
    }

    string typeString() const {
        switch(type){
            case ecdat::AssetType::Symmetric:
                return "Symmetric Cipher";
            case ecdat::AssetType::Asymmetric:
                return "Asymmetric Key / Signature";
            case ecdat::AssetType::Hash:
                return "Hash Function";
            case ecdat::AssetType::Protocol:
                return "Protocol / Library";
            default:
                return "Unknown";
        }
    }
};
    
}