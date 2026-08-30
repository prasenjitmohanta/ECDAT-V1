#pragma once

// ============================================================
//  MoscaEngine.h  —  Mosca's Theorem Risk Calculator
//  Formula: If (X + Y) > Z  →  RED ALERT
//    X = how long data must stay secret (years)
//    Y = time needed to migrate to PQC (years)
//    Z = years until a quantum computer arrives
// ============================================================

#include <string>
#include "CryptoFinding.h"

namespace ecdat {

// The three possible outcomes of Mosca's Theorem
enum class MoscaStatus {
    RED_ALERT,      // X+Y > Z  → already vulnerable TODAY
    AMBER_WARNING,  // X+Y > 80% of Z → act soon
    GREEN_SAFE      // plenty of time
};

// Inputs provided by the user via the UI sliders
struct MoscaInput {
    double dataSecrecyLifetime = 15.0;  // X (years)
    double migrationTime       = 3.0;   // Y (years)
    double quantumArrivalTime  = 10.0;  // Z (years)
};

// The computed result
struct MoscaResult {
    MoscaStatus status;
    double      riskScore;        // (X+Y)/Z  — >1.0 = RED
    std::string statusMessage;    // human-readable verdict
    std::string actionRequired;   // what to do
    std::string recommendation;   // step-by-step PQC steps
};

// Engine that performs the calculation and per-asset prioritization
class MoscaEngine {
public:
    MoscaResult calculate(const MoscaInput& input) const;

    // Annotates a single discovered finding with its specific Mosca urgency and priority deadline
    void annotateFinding(CryptoFinding& finding, double globalZ = 10.0) const;
};

} // namespace ecdat
