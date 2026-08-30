#include "../include/MoscaEngine.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace ecdat {

MoscaResult MoscaEngine::calculate(const MoscaInput& input) const {
    MoscaResult result;

    double total     = input.dataSecrecyLifetime + input.migrationTime;
    result.riskScore = total / input.quantumArrivalTime;

    auto fmt = [](double v) {
        std::ostringstream s;
        s << std::fixed << std::setprecision(1) << v;
        return s.str();
    };

    if (total > input.quantumArrivalTime) {
        // ── RED ALERT ──────────────────────────────────────────
        result.status = MoscaStatus::RED_ALERT;
        result.statusMessage =
            "CRITICAL — X+Y (" + fmt(total) + " yrs) exceeds Z ("
            + fmt(input.quantumArrivalTime) + " yrs). "
            "Harvest-Now-Decrypt-Later attacks make this data "
            "ALREADY AT RISK TODAY.";
        result.actionRequired =
            "Initiate emergency PQC hybrid migration immediately.";
        result.recommendation =
            "1. Deploy ML-KEM-768 (Kyber) for all key encapsulation.\n"
            "2. Deploy ML-DSA-65 (Dilithium) for all digital signatures.\n"
            "3. Enable TLS 1.3 with X25519+Kyber hybrid key exchange.\n"
            "4. Re-encrypt all archived data with AES-256-GCM.\n"
            "5. Replace all X.509 certificates with PQC-hybrid certs.";
    } else if (result.riskScore > 0.80) {
        // ── AMBER WARNING ──────────────────────────────────────
        result.status = MoscaStatus::AMBER_WARNING;
        result.statusMessage =
            "WARNING — Only " + fmt(input.quantumArrivalTime - total)
            + " years margin left. Migration must begin within 6 months.";
        result.actionRequired =
            "Begin PQC migration planning now. Prioritise CRITICAL assets.";
        result.recommendation =
            "1. Audit all CRITICAL-level crypto assets.\n"
            "2. Begin phased ML-KEM / ML-DSA deployment.\n"
            "3. Plan certificate lifecycle updates.";
    } else {
        // ── GREEN SAFE ─────────────────────────────────────────
        result.status = MoscaStatus::GREEN_SAFE;
        result.statusMessage =
            "SAFE — " + fmt(input.quantumArrivalTime - total)
            + " years margin available. Start planning now.";
        result.actionRequired =
            "Monitor NIST PQC standards. Begin awareness and planning.";
        result.recommendation =
            "1. Track NIST PQC updates (FIPS 203/204/205).\n"
            "2. Evaluate liboqs, BoringSSL PQC, OpenSSL oqs-provider.\n"
            "3. Design systems for crypto-agility (easy cipher swap).";
    }

    return result;
}

void MoscaEngine::annotateFinding(CryptoFinding& finding, double globalZ) const {
    std::string a = finding.algorithmName;
    std::transform(a.begin(), a.end(), a.begin(), ::toupper);

    // 1. Asymmetric Public Key / PKI (RSA, ECC, ECDSA, DH) — Broken by Shor's Algo
    // Directly vulnerable to Harvest-Now-Decrypt-Later (HNDL)
    if (a.find("RSA") != std::string::npos || a.find("ECC") != std::string::npos ||
        a.find("ECDSA") != std::string::npos || a.find("DH") != std::string::npos ||
        finding.type == FindingType::KEY_MATERIAL || finding.type == FindingType::PROTOCOL_CONFIG) {
        finding.moscaX = (a.find("CERT") != std::string::npos || finding.type == FindingType::KEY_MATERIAL) ? 20.0 : 15.0;
        finding.moscaY = 3.0;
        finding.quantumMargin = globalZ - (finding.moscaX + finding.moscaY);
        finding.urgencyRank = 1;
        finding.fixUrgency = "IMMEDIATE";
        finding.fixDeadline = "Fix TODAY (HNDL Active)";
    }
    // 2. Legacy Ciphers & Weak Hashes (DES, 3DES, RC4, MD5)
    else if (a.find("DES") != std::string::npos || a.find("RC4") != std::string::npos || a.find("MD5") != std::string::npos) {
        finding.moscaX = 5.0;
        finding.moscaY = 1.0;
        finding.quantumMargin = globalZ - (finding.moscaX + finding.moscaY);
        finding.urgencyRank = 2;
        finding.fixUrgency = "HIGH";
        finding.fixDeadline = "Within 6-12 Months";
    }
    // 3. Symmetric Ciphers with 128-bit keys (AES-128, SHA-1) — Weakened by Grover's
    else if (a.find("AES-128") != std::string::npos || a.find("SHA-1") != std::string::npos || a.find("SHA1") != std::string::npos || a == "AES") {
        finding.moscaX = 10.0;
        finding.moscaY = 1.0;
        finding.quantumMargin = globalZ - (finding.moscaX + finding.moscaY);
        finding.urgencyRank = 3;
        finding.fixUrgency = "MODERATE";
        finding.fixDeadline = "Upgrade to 256-bit";
    }
    // 4. Quantum-Safe (AES-256, SHA-256/384/512, ML-KEM, ML-DSA)
    else {
        finding.moscaX = 5.0;
        finding.moscaY = 0.5;
        finding.quantumMargin = globalZ - (finding.moscaX + finding.moscaY);
        finding.urgencyRank = 4;
        finding.fixUrgency = "SAFE";
        finding.fixDeadline = "Quantum-Resistant";
    }
}

} // namespace ecdat
