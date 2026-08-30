#include "../include/yara_scanner.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace ecdat {

YaraScanner::YaraScanner() {}
YaraScanner::~YaraScanner() {}

static std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

std::vector<uint8_t> YaraScanner::parseHexPattern(const std::string& hexStr) {
    std::vector<uint8_t> bytes;
    std::string clean = "";
    for (char c : hexStr) {
        if (std::isxdigit(c)) {
            clean += c;
        }
    }
    for (size_t i = 0; i + 1 < clean.size(); i += 2) {
        std::string byteString = clean.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

bool YaraScanner::parseYaraFile(const std::string& content) {
    std::istringstream stream(content);
    std::string line;
    YaraRule currentRule;
    bool inRule = false;
    bool inMeta = false;
    bool inStrings = false;

    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line.rfind("//", 0) == 0 || line.rfind("/*", 0) == 0) continue;

        if (line.rfind("rule ", 0) == 0) {
            if (inRule && !currentRule.ruleName.empty()) {
                rules.push_back(currentRule);
                currentRule = YaraRule();
            }
            inRule = true;
            size_t start = 5;
            size_t end = line.find_first_of(" {", start);
            currentRule.ruleName = line.substr(start, end - start);
            continue;
        }

        if (!inRule) continue;

        if (line == "meta:") {
            inMeta = true; inStrings = false; continue;
        } else if (line == "strings:") {
            inMeta = false; inStrings = true; continue;
        } else if (line.rfind("condition:", 0) == 0) {
            inMeta = false; inStrings = false; continue;
        } else if (line == "}") {
            if (!currentRule.ruleName.empty()) {
                rules.push_back(currentRule);
                currentRule = YaraRule();
            }
            inRule = false; inMeta = false; inStrings = false;
            continue;
        }

        if (inMeta) {
            size_t eqPos = line.find('=');
            if (eqPos != std::string::npos) {
                std::string key = trim(line.substr(0, eqPos));
                std::string val = trim(line.substr(eqPos + 1));
                // Remove quotes
                if (val.front() == '"' && val.back() == '"') val = val.substr(1, val.size() - 2);

                if (key == "description") currentRule.description = val;
                else if (key == "algorithm") currentRule.algorithm = val;
                else if (key == "key_size") currentRule.keySize = std::stoi(val);
                else if (key == "severity") {
                    if (val == "CRITICAL") currentRule.severity = Severity::Critical;
                    else if (val == "SAFE") currentRule.severity = Severity::Safe;
                    else currentRule.severity = Severity::Moderate;
                } else if (key == "asset_type") {
                    if (val == "Asymmetric") currentRule.assetType = AssetType::Asymmetric;
                    else if (val == "Hash") currentRule.assetType = AssetType::Hash;
                    else if (val == "Protocol") currentRule.assetType = AssetType::Protocol;
                    else currentRule.assetType = AssetType::Symmetric;
                }
            }
        } else if (inStrings) {
            size_t eqPos = line.find('=');
            if (eqPos != std::string::npos) {
                std::string val = trim(line.substr(eqPos + 1));
                if (val.front() == '{' && val.find('}') != std::string::npos) {
                    // Hex pattern
                    size_t close = val.find('}');
                    std::string hexContent = val.substr(1, close - 1);
                    auto bytes = parseHexPattern(hexContent);
                    if (!bytes.empty()) currentRule.hexPatterns.push_back(bytes);
                } else if (val.front() == '"') {
                    // ASCII string pattern
                    size_t secondQuote = val.find('"', 1);
                    if (secondQuote != std::string::npos) {
                        std::string strContent = val.substr(1, secondQuote - 1);
                        currentRule.textPatterns.push_back(strContent);
                    }
                }
            }
        }
    }

    if (inRule && !currentRule.ruleName.empty()) {
        rules.push_back(currentRule);
    }

    return !rules.empty();
}

bool YaraScanner::loadRules(const std::filesystem::path& rulesPath) {
    std::ifstream file(rulesPath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[-] Error opening YARA rules file: " << rulesPath << "\n";
        return false;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return parseYaraFile(buffer.str());
}

static bool matchBytesAt(const std::vector<uint8_t>& data, size_t pos, const std::vector<uint8_t>& pattern) {
    if (pos + pattern.size() > data.size()) return false;
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (data[pos + i] != pattern[i]) return false;
    }
    return true;
}

std::vector<CryptoAsset> YaraScanner::scanBinary(const std::filesystem::path& filePath) {
    std::vector<CryptoAsset> assets;
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) return assets;

    // Read binary file data into memory
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (buffer.empty()) return assets;

    for (const auto& rule : rules) {
        bool ruleMatched = false;
        size_t matchOffset = 0;
        std::string matchDetail = "";

        // 1. Scan Hex Byte Patterns (e.g. AES S-Boxes, SHA Constants)
        for (const auto& hexPat : rule.hexPatterns) {
            for (size_t i = 0; i + hexPat.size() <= buffer.size(); ++i) {
                if (matchBytesAt(buffer, i, hexPat)) {
                    ruleMatched = true;
                    matchOffset = i;
                    std::stringstream ss;
                    ss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << matchOffset;
                    matchDetail = "Byte sequence match at offset " + ss.str();
                    break;
                }
            }
            if (ruleMatched) break;
        }

        // 2. Scan Text Patterns (e.g. OpenSSL and Windows CNG Symbols)
        if (!ruleMatched) {
            for (const auto& textPat : rule.textPatterns) {
                auto it = std::search(
                    buffer.begin(), buffer.end(),
                    textPat.begin(), textPat.end()
                );
                if (it != buffer.end()) {
                    ruleMatched = true;
                    matchOffset = std::distance(buffer.begin(), it);
                    std::stringstream ss;
                    ss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << matchOffset;
                    matchDetail = "String \"" + textPat + "\" at offset " + ss.str();
                    break;
                }
            }
        }

        if (ruleMatched) {
            assets.push_back({
                filePath.string(),
                std::nullopt,
                rule.assetType,
                rule.algorithm,
                rule.keySize,
                std::nullopt,
                rule.severity,
                "HIGH (100% Binary Signature Match)",
                SourceStage::YARA_Scanner,
                "Rule [" + rule.ruleName + "] -> " + matchDetail
            });
        }
    }

    return assets;
}

std::vector<CryptoAsset> YaraScanner::scanDirectory(const std::filesystem::path& dirPath) {
    std::vector<CryptoAsset> allAssets;
    if (!std::filesystem::exists(dirPath)) return allAssets;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            // Scan binary files
            if (ext == ".exe" || ext == ".dll" || ext == ".elf" || ext == ".so" || ext == ".bin" || ext == ".dat") {
                auto binAssets = scanBinary(entry.path());
                allAssets.insert(allAssets.end(), binAssets.begin(), binAssets.end());
            }
        }
    }
    return allAssets;
}

} // namespace ecdat
