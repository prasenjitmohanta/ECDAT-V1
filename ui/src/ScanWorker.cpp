// ================================================================
//  ScanWorker.cpp  —  ECDAT Multi-Stage Discovery Engine
//  High-Performance Dispatch Matching CLI Backend (AST | YARA | ML)
// ================================================================

#include "../include/ScanWorker.h"
#include "../../AST-Parser-main 2/include/ast_parser.hpp"
#include "../../AST-Parser-main 2/include/yara_scanner.hpp"
#include "../../AST-Parser-main 2/include/ml_bridge.hpp"
#include "../../AST-Parser-main 2/include/models.hpp"
#include "../../core/include/MoscaEngine.h"

#include <QThread>
#include <QCoreApplication>
#include <QDir>
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <set>

namespace fs = std::filesystem;

ScanWorker::ScanWorker(QObject* parent) : QThread(parent) {}

void ScanWorker::configure(const QString& targetPath,
                            bool scanSource, bool scanBinary,
                            bool scanCert,   const QString& projectName) {
    m_targetPath    = targetPath;
    m_scanSource    = scanSource;
    m_scanBinary    = scanBinary;
    m_scanCert      = scanCert;
    m_projectName   = projectName;
    m_stopRequested = false;
}

static std::string getPqcReplacement(const std::string& algo, ecdat::Severity severity) {
    std::string a = algo;
    std::transform(a.begin(), a.end(), a.begin(), ::toupper);

    if (a.find("RSA") != std::string::npos) {
        return "ML-KEM-768 (Kyber) / ML-DSA-65 (Dilithium)";
    }
    if (a.find("ECC") != std::string::npos || a.find("ECDSA") != std::string::npos) {
        return "ML-DSA-65 (Dilithium) / SLH-DSA";
    }
    if (a.find("DH") != std::string::npos) {
        return "ML-KEM-1024 (Kyber)";
    }
    if (a.find("MD5") != std::string::npos) {
        return "SHA-3-256 / SHA-512";
    }
    if (a.find("SHA-1") != std::string::npos || a.find("SHA1") != std::string::npos) {
        return "SHA-256 / SHA-3-256";
    }
    if (a.find("DES") != std::string::npos || a.find("3DES") != std::string::npos) {
        return "AES-256-GCM";
    }
    if (a.find("AES-128") != std::string::npos) {
        return "Upgrade to AES-256-GCM";
    }
    if (a.find("RC4") != std::string::npos) {
        return "ChaCha20-Poly1305";
    }
    if (a.find("BLOWFISH") != std::string::npos || a.find("CAST") != std::string::npos) {
        return "AES-256-GCM";
    }
    if (a.find("TLS") != std::string::npos) {
        return "TLS 1.3 with Hybrid Post-Quantum";
    }
    if (severity == ecdat::Severity::Safe) {
        return "Already Quantum-Resistant";
    }
    return "NIST PQC Migration Recommended";
}

void ScanWorker::run() {
    try {
        fs::path root(m_targetPath.toStdString());

        if (!fs::exists(root)) {
            emit errorOccurred(QString("Target path does not exist: %1").arg(m_targetPath));
            return;
        }

        // Initialize AST & YARA Engines from AST-Parser-main 2
        ecdat::AstScanner  astScanner;
        ecdat::YaraScanner yaraScanner;

        QString appDirStr = QCoreApplication::applicationDirPath();
        QDir appDir(appDirStr);

        // 1. Resolve YARA rules path
        std::string rulesPath = "";
        QStringList ruleCandidates = {
            appDir.filePath("rules/crypto_signatures.yar"),
            appDir.filePath("../Resources/rules/crypto_signatures.yar"),
            appDir.filePath("AST-Parser-main 2/rules/crypto_signatures.yar"),
            "rules/crypto_signatures.yar",
            "AST-Parser-main 2/rules/crypto_signatures.yar",
            "/Users/prasenjit/Desktop/SIH/ECDAT/AST-Parser-main 2/rules/crypto_signatures.yar"
        };
        for (const auto& rc : ruleCandidates) {
            if (fs::exists(rc.toStdString())) {
                rulesPath = rc.toStdString();
                break;
            }
        }
        if (!rulesPath.empty()) {
            yaraScanner.loadRules(rulesPath);
        }

        // 2. Resolve Python interpreter
        std::string pythonExe = "";
#ifdef _WIN32
        QString username = qEnvironmentVariable("USERNAME");
        QStringList pyCandidates = {
            appDir.filePath("python/python.exe"),
            appDir.filePath("python.exe"),
            "C:/Users/" + username + "/AppData/Local/Python/bin/python3.12.exe",
            "C:/Users/" + username + "/AppData/Local/Programs/Python/Python312/python.exe",
            "C:/Users/" + username + "/AppData/Local/Programs/Python/Python311/python.exe",
            "python.exe",
            "python",
            "py.exe",
            "py"
        };
#else
        QStringList pyCandidates = {
            "/Users/prasenjit/miniconda3/bin/python3",
            "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3",
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
            "python3",
            "python"
        };
#endif
        for (const auto& pc : pyCandidates) {
            if (pc.contains('/') || pc.contains('\\')) {
                if (fs::exists(pc.toStdString())) {
                    pythonExe = pc.toStdString();
                    break;
                }
            } else {
                pythonExe = pc.toStdString();
                break;
            }
        }
        if (pythonExe.empty()) {
#ifdef _WIN32
            pythonExe = "python";
#else
            pythonExe = "python3";
#endif
        }

        // 3. Resolve ML script (predict.py)
        std::string mlScript = "";
        QStringList scriptCandidates = {
            appDir.filePath("ml_engine/predict.py"),
            appDir.filePath("predict.py"),
            appDir.filePath("../Resources/ml_engine/predict.py"),
            appDir.filePath("AST-Parser-main 2/ml_engine/predict.py"),
            "ml_engine/predict.py",
            "AST-Parser-main 2/ml_engine/predict.py",
            "predict.py",
            "/Users/prasenjit/Desktop/SIH/ECDAT/AST-Parser-main 2/ml_engine/predict.py"
        };
        for (const auto& sc : scriptCandidates) {
            if (fs::exists(sc.toStdString())) {
                mlScript = sc.toStdString();
                break;
            }
        }

        // 4. Resolve Model File (.pkl)
        std::string modelFile = "";
        QStringList modelCandidates = {
            appDir.filePath("models/ciphertext_ml_scanner.pkl"),
            appDir.filePath("models/ecdat_rf_model_36mb.pkl"),
            appDir.filePath("ciphertext_ml_scanner.pkl"),
            appDir.filePath("../Resources/models/ciphertext_ml_scanner.pkl"),
            "models/ciphertext_ml_scanner.pkl",
            "models/ecdat_rf_model_36mb.pkl",
            "ciphertext_ml_scanner.pkl",
            "AST-Parser-main 2/models/ciphertext_ml_scanner.pkl",
            "/Users/prasenjit/Desktop/SIH/ECDAT/models/ciphertext_ml_scanner.pkl"
        };
        for (const auto& mc : modelCandidates) {
            if (fs::exists(mc.toStdString())) {
                modelFile = mc.toStdString();
                break;
            }
        }

        ecdat::MlBridge mlBridge(pythonExe, mlScript, ecdat::ModelTier::Full_36MB);
        if (!modelFile.empty()) {
            mlBridge.setModelPath(modelFile);
        }

        ecdat::FindingList allFindings;

        auto emitAsset = [this, &allFindings](const ecdat::CryptoAsset& asset) {
            ecdat::CryptoFinding f;
            f.id = asset.algorithm + "_" + std::to_string(asset.lineNumber.value_or(1)) + "_" + std::to_string(allFindings.size() + 1);
            f.filePath = asset.filePath;
            f.lineNumber = asset.lineNumber.value_or(0);
            f.algorithmName = asset.algorithm;
            f.algorithmFamily = asset.typeString();
            f.keyLength = asset.keySize.value_or(0);

            switch (asset.severity) {
                case ecdat::Severity::Critical:
                    f.riskLevel = ecdat::RiskLevel::CRITICAL;
                    f.quantumThreat = ecdat::QuantumThreat::BROKEN_BY_SHORS;
                    f.cweId = (asset.type == ecdat::AssetType::Hash) ? "CWE-328" : "CWE-327";
                    break;
                case ecdat::Severity::Moderate:
                    f.riskLevel = ecdat::RiskLevel::MODERATE;
                    f.quantumThreat = ecdat::QuantumThreat::WEAKENED_BY_GROVERS;
                    f.cweId = "CWE-327";
                    break;
                default:
                    f.riskLevel = ecdat::RiskLevel::SAFE;
                    f.quantumThreat = ecdat::QuantumThreat::QUANTUM_SAFE;
                    f.cweId = "";
                    break;
            }

            f.pqcReplacement = getPqcReplacement(asset.algorithm, asset.severity);
            f.matchedSnippet = asset.evidence;

            if (asset.stage == ecdat::SourceStage::AST_Parser) {
                f.confidence = "100.0%";
                f.scannerSource = "AST Parser";
                f.type = (asset.evidence.find("import") != std::string::npos)
                         ? ecdat::FindingType::LIBRARY_IMPORT
                         : ecdat::FindingType::ALGORITHM_USAGE;
            } else if (asset.stage == ecdat::SourceStage::YARA_Scanner) {
                f.confidence = "100.0%";
                f.scannerSource = "YARA Scanner";
                f.type = ecdat::FindingType::BINARY_SIGNATURE;
            } else if (asset.stage == ecdat::SourceStage::Heuristic_Inference) {
                f.confidence = asset.confidence.empty() ? "85.0%" : asset.confidence;
                f.scannerSource = "ML Inference";
                f.type = ecdat::FindingType::BINARY_SIGNATURE;
            } else {
                f.confidence = "100.0%";
                f.scannerSource = "Config Scanner";
                f.type = ecdat::FindingType::PROTOCOL_CONFIG;
            }

            ecdat::MoscaEngine mosca;
            mosca.annotateFinding(f, 10.0);

            emit findingDiscovered(f);
            allFindings.push_back(f);
        };

        // ═════════════════════════════════════════════════════════════
        // CASE A: SINGLE FILE SCAN (Instant Response — < 5ms)
        // ═════════════════════════════════════════════════════════════
        if (fs::is_regular_file(root)) {
            emit progressUpdate(1, 1, QString::fromStdString(root.filename().string()));

            std::string ext = root.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

            bool isSrc = (ext == ".cpp" || ext == ".c" || ext == ".h" || ext == ".hpp" ||
                          ext == ".cc"  || ext == ".cxx" || ext == ".py" || ext == ".java" || ext == ".go");

            if (isSrc) {
                // Stage 1: Static AST Source Scanner (Instant C++ Tree-Sitter)
                auto astAssets = astScanner.scanFile(root);
                for (const auto& a : astAssets) emitAsset(a);
            } else {
                // Stage 2: YARA Binary Signature Scanner
                auto yaraAssets = yaraScanner.scanBinary(root);
                if (!yaraAssets.empty()) {
                    for (const auto& a : yaraAssets) emitAsset(a);
                } else if (ext == ".bin" || ext == ".dat" || ext == ".raw") {
                    // Stage 3: ML Inference via Random Forest Ensemble
                    if (fs::exists(mlScript)) {
                        auto mlAsset = mlBridge.triageBinaryBlob(root);
                        if (mlAsset.has_value()) emitAsset(*mlAsset);
                    }
                }
            }

            emit scanCompleted(allFindings);
            return;
        }

        // ═════════════════════════════════════════════════════════════
        // CASE B: DIRECTORY SCAN (Vectorized & High Performance)
        // ═════════════════════════════════════════════════════════════
        std::vector<fs::path> allFiles;
        for (const auto& entry : fs::recursive_directory_iterator(root)) {
            if (m_stopRequested) break;
            if (entry.is_regular_file()) {
                allFiles.push_back(entry.path());
            }
        }

        int total = static_cast<int>(allFiles.size());
        if (total == 0) total = 1;

        std::vector<fs::path> unlabelledBlobs;
        int current = 0;

        for (const auto& filePath : allFiles) {
            if (m_stopRequested) break;

            current++;
            emit progressUpdate(current, total, QString::fromStdString(filePath.filename().string()));

            std::string ext = filePath.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

            bool isSrc = (ext == ".cpp" || ext == ".c" || ext == ".h" || ext == ".hpp" ||
                          ext == ".cc"  || ext == ".cxx" || ext == ".py" || ext == ".java" || ext == ".go");
            bool isBin = (ext == ".exe" || ext == ".dll" || ext == ".elf" || ext == ".so" ||
                          ext == ".bin" || ext == ".dat" || ext == ".raw" || ext == ".dylib");

            if (m_scanSource && isSrc) {
                auto astAssets = astScanner.scanFile(filePath);
                for (const auto& a : astAssets) emitAsset(a);
            } else if (m_scanBinary && isBin) {
                auto yaraAssets = yaraScanner.scanBinary(filePath);
                if (!yaraAssets.empty()) {
                    for (const auto& a : yaraAssets) emitAsset(a);
                } else if (ext == ".bin" || ext == ".dat" || ext == ".raw") {
                    unlabelledBlobs.push_back(filePath);
                }
            }
        }

        // Stage 3: Vectorized Single-Batch Predictive ML Inference (Random Forest Hierarchical Ensemble)
        if (m_scanBinary && !unlabelledBlobs.empty() && !m_stopRequested && fs::exists(mlScript)) {
            auto mlFindings = mlBridge.triageBatch(unlabelledBlobs);
            for (const auto& a : mlFindings) {
                emitAsset(a);
            }
        }

        emit scanCompleted(allFindings);

    } catch (const std::exception& ex) {
        emit errorOccurred(QString("Discovery Engine Error: %1").arg(ex.what()));
    }
}
