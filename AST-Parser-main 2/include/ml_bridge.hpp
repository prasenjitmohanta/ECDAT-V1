#pragma once

#include "models.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <optional>

namespace ecdat {

enum class ModelTier {
    Full_36MB,
    Light_6MB
};

class MlBridge {
public:
    MlBridge(
        std::string pythonInterpreter = "python",
        std::string scriptPath = "ml_engine/predict.py",
        ModelTier tier = ModelTier::Full_36MB
    );
    ~MlBridge();

    void setModelTier(ModelTier tier);
    void setModelPath(std::string path);

    // Single File Triage
    std::optional<CryptoAsset> triageBinaryBlob(const std::filesystem::path& filePath);

    // Batch File Triage (Accelerated - Loads model weights ONCE)
    std::vector<CryptoAsset> triageBatch(const std::vector<std::filesystem::path>& filePaths);

    // Directory Triage
    std::vector<CryptoAsset> triageDirectory(const std::filesystem::path& dirPath);

private:
    std::string pythonExe;
    std::string script;
    std::string modelPath;

    std::vector<CryptoAsset> parseJsonBatch(const std::string& jsonStr);
};

} // namespace ecdat
