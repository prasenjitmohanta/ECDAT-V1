#pragma once

#include "models.hpp"
#include <string>
#include <vector>
#include <filesystem>

namespace ecdat {

class AstScanner {
public:
    AstScanner();
    ~AstScanner();

    // Scans a single source file (.cpp, .c, .h, .hpp, .py)
    std::vector<CryptoAsset> scanFile(const std::filesystem::path& filePath);

    // Recursively scans an entire directory
    std::vector<CryptoAsset> scanDirectory(const std::filesystem::path& dirPath);

private:
    std::vector<CryptoAsset> parseCpp(const std::string& code, const std::string& filePath);
    std::vector<CryptoAsset> parsePython(const std::string& code, const std::string& filePath);

    int getLineNumber(const std::string& code, size_t byteOffset);
};

} // namespace ecdat