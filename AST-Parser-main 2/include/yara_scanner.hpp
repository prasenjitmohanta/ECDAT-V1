#pragma once

#include "models.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <optional>
#include <cstdint>

namespace ecdat {

struct YaraRule {
    std::string ruleName;
    std::string description;
    std::string algorithm;
    AssetType assetType{AssetType::Symmetric};
    std::optional<int> keySize{std::nullopt};
    Severity severity{Severity::Moderate};
    std::vector<std::vector<uint8_t>> hexPatterns;
    std::vector<std::string> textPatterns;
    bool isAnyCondition{true};
};

class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();

    // Loads and compiles .yar rule files
    bool loadRules(const std::filesystem::path& rulesPath);

    // Scans a single binary file (.exe, .dll, .elf, .so, .bin)
    std::vector<CryptoAsset> scanBinary(const std::filesystem::path& filePath);

    // Recursively scans an entire directory for binaries
    std::vector<CryptoAsset> scanDirectory(const std::filesystem::path& dirPath);

private:
    std::vector<YaraRule> rules;
    bool parseYaraFile(const std::string& content);
    std::vector<uint8_t> parseHexPattern(const std::string& hexStr);
};

} // namespace ecdat
