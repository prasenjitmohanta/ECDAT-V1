#include "../include/ml_bridge.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <memory>
#include <array>

namespace ecdat {

MlBridge::MlBridge(std::string pythonInterpreter, std::string scriptPath, ModelTier tier)
    : pythonExe(std::move(pythonInterpreter)), script(std::move(scriptPath)) {
    setModelTier(tier);
}

MlBridge::~MlBridge() {}

void MlBridge::setModelTier(ModelTier tier) {
    if (tier == ModelTier::Light_6MB) {
        modelPath = "models/ecdat_rf_model_6mb.pkl";
    } else {
        modelPath = "models/ecdat_rf_model_36mb.pkl";
    }
}

std::vector<CryptoAsset> MlBridge::parseJsonBatch(const std::string& jsonStr) {
    std::vector<CryptoAsset> assets;
    if (jsonStr.empty() || jsonStr.find("[") == std::string::npos) {
        return assets;
    }

    size_t pos = 0;
    while ((pos = jsonStr.find("{\"file_path\": \"", pos)) != std::string::npos) {
        size_t objEnd = jsonStr.find("}", pos);
        if (objEnd == std::string::npos) break;

        std::string chunk = jsonStr.substr(pos, objEnd - pos + 1);
        pos = objEnd + 1;

        // 1. file_path
        std::string filePath = "";
        size_t fpPos = chunk.find("\"file_path\": \"");
        if (fpPos != std::string::npos) {
            size_t s = fpPos + 14;
            size_t e = chunk.find("\"", s);
            if (e != std::string::npos) filePath = chunk.substr(s, e - s);
        }

        // 2. predicted_algorithm
        std::string algo = "Symmetric (Unknown)";
        size_t algoPos = chunk.find("\"predicted_algorithm\": \"");
        if (algoPos != std::string::npos) {
            size_t s = algoPos + 24;
            size_t e = chunk.find("\"", s);
            if (e != std::string::npos) algo = chunk.substr(s, e - s);
        }

        // 3. confidence
        std::string confStr = "HIGH";
        size_t confPos = chunk.find("\"confidence_percent\": ");
        if (confPos != std::string::npos) {
            size_t s = confPos + 22;
            size_t e = chunk.find_first_of(",}", s);
            if (e != std::string::npos) confStr = chunk.substr(s, e - s) + "%";
        }

        // 4. severity
        Severity sev = Severity::Moderate;
        if (chunk.find("\"severity\": \"CRITICAL\"") != std::string::npos) {
            sev = Severity::Critical;
        } else if (chunk.find("\"severity\": \"SAFE\"") != std::string::npos) {
            sev = Severity::Safe;
        }

        // 5. entropy
        std::string entropyStr = "";
        size_t entPos = chunk.find("\"entropy\": ");
        if (entPos != std::string::npos) {
            size_t s = entPos + 11;
            size_t e = chunk.find_first_of(",}", s);
            if (e != std::string::npos) {
                entropyStr = " (Shannon Entropy: " + chunk.substr(s, e - s) + ")";
            }
        }

        AssetType type = AssetType::Symmetric;
        if (algo == "RSA" || algo == "ECC") type = AssetType::Asymmetric;
        else if (algo.find("SHA") != std::string::npos || algo == "MD5") type = AssetType::Hash;

        // Zero-Trust Cryptographic Principle:
        // Key sizes CANNOT be derived from pure ciphertext by ML.
        std::optional<int> keySize = std::nullopt;

        assets.push_back({
            filePath,
            std::nullopt,
            type,
            algo,
            keySize,
            std::nullopt,
            sev,
            confStr,
            SourceStage::Heuristic_Inference,
            "NIST SP 800-22 Heuristic Inference" + entropyStr + " -> Confidence: " + confStr
        });
    }

    return assets;
}

std::vector<CryptoAsset> MlBridge::triageBatch(const std::vector<std::filesystem::path>& filePaths) {
    std::vector<CryptoAsset> assets;
    if (filePaths.empty()) return assets;

    // Write file paths to a temporary manifest file to bypass Windows 8191-character command line limit
    std::filesystem::path manifestPath = std::filesystem::temp_directory_path() / "ecdat_batch_manifest.txt";
    {
        std::ofstream manifest(manifestPath);
        for (const auto& p : filePaths) {
            manifest << p.string() << "\n";
        }
    }

    std::string cmd = "\"" + pythonExe + "\" \"" + script + "\" --model \"" + modelPath + "\" --manifest \"" + manifestPath.string() + "\"";

#ifdef _WIN32
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif

    if (!pipe) {
        std::filesystem::remove(manifestPath);
        return assets;
    }

    std::string result = "";
    std::array<char, 4096> buffer;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }

#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif

    std::filesystem::remove(manifestPath);
    return parseJsonBatch(result);
}

std::optional<CryptoAsset> MlBridge::triageBinaryBlob(const std::filesystem::path& filePath) {
    auto res = triageBatch({filePath});
    if (!res.empty()) return res.front();
    return std::nullopt;
}

std::vector<CryptoAsset> MlBridge::triageDirectory(const std::filesystem::path& dirPath) {
    std::vector<std::filesystem::path> blobs;
    if (!std::filesystem::exists(dirPath)) return {};

    for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            if (ext == ".bin" || ext == ".dat" || ext == ".raw" || ext == ".blob") {
                blobs.push_back(entry.path());
            }
        }
    }
    return triageBatch(blobs);
}

} // namespace ecdat
