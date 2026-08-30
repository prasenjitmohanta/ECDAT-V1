#include "../include/ast_parser.hpp"
#include "../include/yara_scanner.hpp"
#include "../include/ml_bridge.hpp"
#include <iostream>
#include <iomanip>
#include <map>
#include <vector>
#include <string>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
void enableVirtualTerminal() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}
#else
void enableVirtualTerminal() {}
#endif

namespace ui {
    const std::string RESET       = "\033[0m";
    const std::string BOLD        = "\033[1m";
    const std::string DIM         = "\033[2m";
    
    // Colors
    const std::string RED         = "\033[31m";
    const std::string GREEN       = "\033[32m";
    const std::string YELLOW      = "\033[33m";
    const std::string BLUE        = "\033[34m";
    const std::string MAGENTA     = "\033[35m";
    const std::string CYAN        = "\033[36m";
    const std::string WHITE       = "\033[37m";
    const std::string GRAY        = "\033[90m";
    
    // Bold Colors
    const std::string B_RED       = "\033[1;31m";
    const std::string B_GREEN     = "\033[1;32m";
    const std::string B_YELLOW    = "\033[1;33m";
    const std::string B_BLUE      = "\033[1;34m";
    const std::string B_MAGENTA   = "\033[1;35m";
    const std::string B_CYAN      = "\033[1;36m";
    const std::string B_WHITE     = "\033[1;37m";

    // Badges
    const std::string BADGE_CRIT  = "\033[41;1;37m CRITICAL \033[0m";
    const std::string BADGE_MOD   = "\033[43;1;30m MODERATE \033[0m";
    const std::string BADGE_SAFE  = "\033[42;1;37m   SAFE   \033[0m";
}

int main(int argc, char* argv[]) {
    enableVirtualTerminal();

    std::filesystem::path targetPath = "./test_samples";
    std::filesystem::path rulesPath = "./rules/crypto_signatures.yar";
    ecdat::ModelTier selectedTier = ecdat::ModelTier::Full_36MB;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--light") {
            selectedTier = ecdat::ModelTier::Light_6MB;
        } else if (arg.rfind("--", 0) != 0) {
            targetPath = arg;
        }
    }

    std::string modelName = (selectedTier == ecdat::ModelTier::Full_36MB) 
                            ? "ecdat_rf_model_36mb.pkl (36MB Full Random Forest)" 
                            : "ecdat_rf_model_6mb.pkl (6MB Lightweight Random Forest)";

    // Banner
    std::cout << ui::B_CYAN;
    std::cout << "╭─────────────────────────────────────────────────────────────────────────────╮\n";
    std::cout << "│   " << ui::B_WHITE << "███████╗ ██████╗██████╗  █████╗ ████████╗" << ui::B_CYAN << "                                 │\n";
    std::cout << "│   " << ui::B_WHITE << "██╔════╝██╔════╝██╔══██╗██╔══██╗╚══██╔══╝" << ui::CYAN << "  Enterprise Cryptographic       │\n";
    std::cout << "│   " << ui::B_WHITE << "█████╗  ██║     ██║  ██║███████║   ██║   " << ui::CYAN << "  Discovery & Audit Engine       │\n";
    std::cout << "│   " << ui::B_WHITE << "██╔══╝  ██║     ██║  ██║██╔══██║   ██║   " << ui::GRAY << "  Multi-Stage Zero-Trust Engine  │\n";
    std::cout << "│   " << ui::B_WHITE << "███████╗╚██████╗██████╔╝██║  ██║   ██║   " << ui::B_YELLOW << "  v2.4 [AST | YARA | Inference]  " << ui::B_CYAN << "│\n";
    std::cout << "│   " << ui::B_WHITE << "╚══════╝ ╚═════╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   " << ui::DIM << "  National Post-Quantum PQC 2026 " << ui::B_CYAN << "│\n";
    std::cout << "╰─────────────────────────────────────────────────────────────────────────────╯\n" << ui::RESET;

    // Scan Configuration Box
    std::cout << ui::B_WHITE << "\n┌── [SCAN CONFIGURATION] ───────────────────────────────────────────────────────\n" << ui::RESET;
    std::cout << "│  " << ui::B_WHITE << "Target Scope      : " << ui::B_CYAN << targetPath.string() << ui::RESET << "\n";
    std::cout << "│  " << ui::B_WHITE << "Stage 1 Engine    : " << ui::B_MAGENTA << "Tree-Sitter C/C++ & Python AST Semantic Parser" << ui::RESET << "\n";
    std::cout << "│  " << ui::B_WHITE << "Stage 2 Engine    : " << ui::B_YELLOW << "YARA Binary & S-Box Signature Scanner (" << rulesPath.string() << ")" << ui::RESET << "\n";
    std::cout << "│  " << ui::B_WHITE << "Stage 3 Engine    : " << ui::B_BLUE << "Blind Heuristic & Statistical Classifier (" << modelName << ")" << ui::RESET << "\n";
    std::cout << ui::B_WHITE << "└──────────────────────────────────────────────────────────────────────────────\n\n" << ui::RESET;

    ecdat::AstScanner astScanner;
    ecdat::YaraScanner yaraScanner;
    ecdat::MlBridge mlBridge("C:/Users/debas/AppData/Local/Python/bin/python3.12.exe", "ml_engine/predict.py", selectedTier);

    if (!yaraScanner.loadRules(rulesPath)) {
        std::cerr << ui::B_RED << "[!] Warning: Could not load YARA rules from " << rulesPath << ui::RESET << "\n";
    }

    std::vector<ecdat::CryptoAsset> rawFindings;
    int totalFilesScanned = 0;

    // High-Resolution Benchmarking Timers
    auto totalScanStart = std::chrono::high_resolution_clock::now();
    double stage1Ms = 0.0, stage2Ms = 0.0, stage3Ms = 0.0;

    if (std::filesystem::is_directory(targetPath)) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(targetPath)) {
            if (entry.is_regular_file()) totalFilesScanned++;
        }

        // Stage 1: AST Source Scanning
        auto t1_start = std::chrono::high_resolution_clock::now();
        auto astFindings = astScanner.scanDirectory(targetPath);
        auto t1_end = std::chrono::high_resolution_clock::now();
        stage1Ms = std::chrono::duration<double, std::milli>(t1_end - t1_start).count();
        rawFindings.insert(rawFindings.end(), astFindings.begin(), astFindings.end());

        // Stage 2: YARA Executable Scanning
        auto t2_start = std::chrono::high_resolution_clock::now();
        auto yaraFindings = yaraScanner.scanDirectory(targetPath);
        auto t2_end = std::chrono::high_resolution_clock::now();
        stage2Ms = std::chrono::duration<double, std::milli>(t2_end - t2_start).count();
        rawFindings.insert(rawFindings.end(), yaraFindings.begin(), yaraFindings.end());

        // Stage 3: Collect All Unlabelled Binary Blobs for Batch Inference
        std::vector<std::filesystem::path> unlabelledBlobs;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(targetPath)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                if (ext == ".bin" || ext == ".dat" || ext == ".raw") {
                    bool matchedByYara = false;
                    for (const auto& yf : yaraFindings) {
                        if (yf.filePath == entry.path().string()) {
                            matchedByYara = true;
                            break;
                        }
                    }
                    if (!matchedByYara) {
                        unlabelledBlobs.push_back(entry.path());
                    }
                }
            }
        }

        if (!unlabelledBlobs.empty()) {
            auto t3_start = std::chrono::high_resolution_clock::now();
            auto mlFindings = mlBridge.triageBatch(unlabelledBlobs);
            auto t3_end = std::chrono::high_resolution_clock::now();
            stage3Ms = std::chrono::duration<double, std::milli>(t3_end - t3_start).count();
            rawFindings.insert(rawFindings.end(), mlFindings.begin(), mlFindings.end());
        }
    } else {
        totalFilesScanned = 1;
        std::string ext = targetPath.extension().string();
        if (ext == ".cpp" || ext == ".c" || ext == ".h" || ext == ".hpp" || ext == ".py") {
            auto t1_start = std::chrono::high_resolution_clock::now();
            auto astFindings = astScanner.scanFile(targetPath);
            auto t1_end = std::chrono::high_resolution_clock::now();
            stage1Ms = std::chrono::duration<double, std::milli>(t1_end - t1_start).count();
            rawFindings.insert(rawFindings.end(), astFindings.begin(), astFindings.end());
        } else {
            auto t2_start = std::chrono::high_resolution_clock::now();
            auto yaraFindings = yaraScanner.scanBinary(targetPath);
            auto t2_end = std::chrono::high_resolution_clock::now();
            stage2Ms = std::chrono::duration<double, std::milli>(t2_end - t2_start).count();

            if (!yaraFindings.empty()) {
                rawFindings.insert(rawFindings.end(), yaraFindings.begin(), yaraFindings.end());
            } else if (ext == ".bin" || ext == ".dat" || ext == ".raw") {
                auto t3_start = std::chrono::high_resolution_clock::now();
                auto mlAsset = mlBridge.triageBinaryBlob(targetPath);
                auto t3_end = std::chrono::high_resolution_clock::now();
                stage3Ms = std::chrono::duration<double, std::milli>(t3_end - t3_start).count();
                if (mlAsset.has_value()) {
                    rawFindings.push_back(*mlAsset);
                }
            }
        }
    }

    auto totalScanEnd = std::chrono::high_resolution_clock::now();
    double totalScanSec = std::chrono::duration<double>(totalScanEnd - totalScanStart).count();

    // -------------------------------------------------------------------------
    // Aggregate occurrences per (File + Algorithm)
    // -------------------------------------------------------------------------
    struct AggregatedAsset {
        ecdat::CryptoAsset base;
        std::vector<int> lineNumbers;
        std::vector<std::string> evidences;
    };

    std::map<std::string, AggregatedAsset> aggregatedMap;
    int countCrit = 0, countMod = 0, countSafe = 0;
    int countStage1 = 0, countStage2 = 0, countStage3 = 0;

    for (const auto& item : rawFindings) {
        std::string key = item.filePath + "::" + item.algorithm;
        if (aggregatedMap.find(key) == aggregatedMap.end()) {
            AggregatedAsset agg;
            agg.base = item;
            if (item.lineNumber.has_value()) {
                agg.lineNumbers.push_back(item.lineNumber.value());
            }
            agg.evidences.push_back(item.evidence);
            aggregatedMap[key] = agg;

            if (item.severity == ecdat::Severity::Critical) countCrit++;
            else if (item.severity == ecdat::Severity::Moderate) countMod++;
            else countSafe++;

            if (item.stage == ecdat::SourceStage::AST_Parser) countStage1++;
            else if (item.stage == ecdat::SourceStage::YARA_Scanner) countStage2++;
            else if (item.stage == ecdat::SourceStage::Heuristic_Inference) countStage3++;
        } else {
            if (item.lineNumber.has_value()) {
                aggregatedMap[key].lineNumbers.push_back(item.lineNumber.value());
            }
            aggregatedMap[key].evidences.push_back(item.evidence);
        }
    }

    std::cout << ui::B_WHITE << "Found " << ui::B_CYAN << rawFindings.size() << ui::B_WHITE 
              << " raw cryptographic references across " << ui::B_CYAN << aggregatedMap.size() 
              << ui::B_WHITE << " unique components.\n\n" << ui::RESET;

    int index = 1;
    for (const auto& [key, item] : aggregatedMap) {
        const auto& asset = item.base;
        
        std::string stageBadge = "";
        std::string cardBorderColor = ui::CYAN;

        if (asset.stage == ecdat::SourceStage::AST_Parser) {
            stageBadge = ui::B_MAGENTA + "[STAGE 1: AST CODE PARSER]" + ui::RESET;
            cardBorderColor = ui::MAGENTA;
        } else if (asset.stage == ecdat::SourceStage::YARA_Scanner) {
            stageBadge = ui::B_YELLOW + "[STAGE 2: YARA BINARY ENGINE]" + ui::RESET;
            cardBorderColor = ui::YELLOW;
        } else {
            stageBadge = ui::B_BLUE + "[STAGE 3: BLIND CIPHERTEXT INFERENCE]" + ui::RESET;
            cardBorderColor = ui::BLUE;
        }

        std::string riskBadge = "";
        if (asset.severity == ecdat::Severity::Critical) {
            riskBadge = ui::BADGE_CRIT + " " + ui::B_RED + "Quantum Broken / Deprecated" + ui::RESET;
        } else if (asset.severity == ecdat::Severity::Moderate) {
            riskBadge = ui::BADGE_MOD + " " + ui::B_YELLOW + "Quantum Weakened" + ui::RESET;
        } else {
            riskBadge = ui::BADGE_SAFE + " " + ui::B_GREEN + "Post-Quantum Resistant" + ui::RESET;
        }

        // Header Card
        std::cout << cardBorderColor << "╭── [" << std::setw(2) << std::setfill('0') << index++ << "] " 
                  << ui::B_WHITE << asset.algorithm << " " << cardBorderColor 
                  << "─────────────────────────────────────────────────────────────────────────────\n" << ui::RESET;
        
        std::cout << cardBorderColor << "│  " << ui::WHITE << "Stage        : " << stageBadge << "\n";
        std::cout << cardBorderColor << "│  " << ui::WHITE << "Asset Type   : " << ui::B_WHITE << asset.typeString() << ui::RESET << "\n";
        std::cout << cardBorderColor << "│  " << ui::WHITE << "Location     : " << ui::B_CYAN << asset.filePath << ui::RESET;

        if (!item.lineNumbers.empty()) {
            std::cout << ui::WHITE << " (Line" << (item.lineNumbers.size() > 1 ? "s: " : ": ") << ui::B_YELLOW;
            for (size_t l = 0; l < item.lineNumbers.size(); ++l) {
                std::cout << item.lineNumbers[l] << (l + 1 < item.lineNumbers.size() ? ", " : "");
            }
            std::cout << ui::WHITE << ")";
        }
        std::cout << "\n";

        // Key Size formatting
        std::string keySizeStr = (asset.keySize.has_value() ? std::to_string(asset.keySize.value()) + " bits" : "N/A");
        if (asset.stage == ecdat::SourceStage::Heuristic_Inference) {
            keySizeStr += " (Zero-Trust: Pure ciphertext does not leak key length)";
        }

        std::cout << cardBorderColor << "│  " << ui::WHITE << "Key Length   : " << ui::B_WHITE << keySizeStr << ui::RESET << "\n";
        std::cout << cardBorderColor << "│  " << ui::WHITE << "Cipher Mode  : " << ui::B_WHITE << asset.mode.value_or("N/A") << ui::RESET << "\n";
        std::cout << cardBorderColor << "│  " << ui::WHITE << "Risk Rating  : " << riskBadge << "\n";
        
        std::cout << cardBorderColor << "│  " << ui::WHITE << "Evidence     : \n";
        for (const auto& ev : item.evidences) {
            std::cout << cardBorderColor << "│    " << ui::GRAY << "- " << ui::WHITE << ev << "\n";
        }

        std::cout << cardBorderColor << "│  " << ui::WHITE << "Remediation  : " 
                  << (asset.severity == ecdat::Severity::Critical ? ui::B_RED : (asset.severity == ecdat::Severity::Moderate ? ui::B_YELLOW : ui::B_GREEN))
                  << "-> " << asset.remediationAdvice() << ui::RESET << "\n";

        if (asset.stage == ecdat::SourceStage::YARA_Scanner || asset.stage == ecdat::SourceStage::Heuristic_Inference) {
            std::cout << cardBorderColor << "│  " << ui::WHITE << "Binary Fix   : " 
                      << ui::CYAN << "Apply PQC DLL Shim wrapper, patch IAT, or wrap in TLS Sidecar proxy." << ui::RESET << "\n";
        }

        std::cout << cardBorderColor << "╰─────────────────────────────────────────────────────────────────────────────\n\n" << ui::RESET;
    }

    // -------------------------------------------------------------------------
    // Performance & Benchmark Metrics Box
    // -------------------------------------------------------------------------
    double filesPerSec = (totalScanSec > 0.0) ? (totalFilesScanned / totalScanSec) : 0.0;

    std::cout << ui::B_WHITE << "===============================================================================\n";
    std::cout << "                    " << ui::B_YELLOW << "⚡ PERFORMANCE & BENCHMARK METRICS" << ui::B_WHITE << "\n";
    std::cout << "===============================================================================\n" << ui::RESET;
    std::cout << "  " << ui::B_WHITE << "Total Files Processed   : " << ui::B_CYAN << totalFilesScanned << " files\n" << ui::RESET;
    std::cout << "  " << ui::B_WHITE << "Total End-to-End Scan   : " << ui::B_GREEN << std::fixed << std::setprecision(2) << totalScanSec << " seconds" 
              << ui::GRAY << " (" << std::fixed << std::setprecision(1) << filesPerSec << " files/sec)\n" << ui::RESET;
    std::cout << ui::GRAY << "  -----------------------------------------------------------------------------\n" << ui::RESET;
    std::cout << "  ├─ " << ui::MAGENTA << "Stage 1 (AST Source Parser)  : " << ui::B_WHITE << std::fixed << std::setprecision(2) << stage1Ms << " ms" 
              << ui::GRAY << " (C++ Tree-Sitter Grammars)\n" << ui::RESET;
    std::cout << "  ├─ " << ui::YELLOW  << "Stage 2 (YARA Binary Engine) : " << ui::B_WHITE << std::fixed << std::setprecision(2) << stage2Ms << " ms" 
              << ui::GRAY << " (Byte Signature Sliding Window)\n" << ui::RESET;
    std::cout << "  └─ " << ui::BLUE    << "Stage 3 (Blind ML Inference) : " << ui::B_WHITE << std::fixed << std::setprecision(2) << stage3Ms << " ms" 
              << ui::GRAY << " (Vectorized Random Forest Batch Inference)\n" << ui::RESET;
    std::cout << ui::B_WHITE << "===============================================================================\n\n" << ui::RESET;

    // -------------------------------------------------------------------------
    // Executive Summary Dashboard
    // -------------------------------------------------------------------------
    double safePercent = (aggregatedMap.empty()) ? 0.0 : (countSafe * 100.0 / aggregatedMap.size());
    double critPercent = (aggregatedMap.empty()) ? 0.0 : (countCrit * 100.0 / aggregatedMap.size());
    double modPercent  = (aggregatedMap.empty()) ? 0.0 : (countMod * 100.0 / aggregatedMap.size());

    std::cout << ui::B_WHITE << "===============================================================================\n";
    std::cout << "                      " << ui::B_CYAN << "EXECUTIVE AUDIT SUMMARY DASHBOARD" << ui::B_WHITE << "\n";
    std::cout << "===============================================================================\n" << ui::RESET;
    
    std::cout << "  " << ui::B_WHITE << "Total Unique Components Audited : " << ui::B_CYAN << aggregatedMap.size() 
              << ui::WHITE << " (" << rawFindings.size() << " Raw Occurrences)\n";
    std::cout << "  |- " << ui::MAGENTA << "Stage 1 (AST Source Parser)   : " << ui::B_WHITE << countStage1 << " Components\n" << ui::RESET;
    std::cout << "  |- " << ui::YELLOW  << "Stage 2 (YARA Binary Engine)  : " << ui::B_WHITE << countStage2 << " Components\n" << ui::RESET;
    std::cout << "  +- " << ui::BLUE    << "Stage 3 (Blind ML Inference)  : " << ui::B_WHITE << countStage3 << " Components\n" << ui::RESET;
    
    std::cout << ui::GRAY << "-------------------------------------------------------------------------------\n" << ui::RESET;
    std::cout << "  " << ui::B_WHITE << "Post-Quantum Cryptographic Breakdown:\n" << ui::RESET;
    std::cout << "  " << ui::BADGE_CRIT << " " << ui::B_RED << countCrit << " Assets (" << std::fixed << std::setprecision(1) << critPercent << "%)" 
              << ui::GRAY << " - Quantum Broken (Immediate Migration Required)\n" << ui::RESET;
    std::cout << "  " << ui::BADGE_MOD  << " " << ui::B_YELLOW << countMod << " Assets (" << std::fixed << std::setprecision(1) << modPercent << "%)" 
              << ui::GRAY << " - Quantum Weakened (Upgrade Key Length)\n" << ui::RESET;
    std::cout << "  " << ui::BADGE_SAFE << " " << ui::B_GREEN << countSafe << " Assets (" << std::fixed << std::setprecision(1) << safePercent << "%)" 
              << ui::GRAY << " - Quantum Resistant (NIST Compliant)\n" << ui::RESET;
    
    std::cout << ui::GRAY << "-------------------------------------------------------------------------------\n" << ui::RESET;
    std::cout << "  " << ui::B_WHITE << "NIST PQC Migration Readiness Score: " 
              << (safePercent >= 70.0 ? ui::B_GREEN : (safePercent >= 40.0 ? ui::B_YELLOW : ui::B_RED)) 
              << std::fixed << std::setprecision(1) << safePercent << "%" << ui::RESET;
    if (safePercent < 50.0) {
        std::cout << ui::B_RED << " [HIGH POST-QUANTUM EXPOSURE RISK]" << ui::RESET;
    } else {
        std::cout << ui::B_GREEN << " [ACCEPTABLE POST-QUANTUM POSTURE]" << ui::RESET;
    }
    std::cout << "\n";
    std::cout << ui::B_WHITE << "===============================================================================\n\n" << ui::RESET;

    return 0;
}
