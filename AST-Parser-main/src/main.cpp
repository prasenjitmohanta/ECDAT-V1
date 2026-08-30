#include "../include/ast_parser.hpp"
#include <iostream>
#include <iomanip>

int main(int argc, char* argv[]) {
    std::cout << "====================================================\n";
    std::cout << "  ECDAT - Multi-Language AST Cryptographic Scanner  \n";
    std::cout << "====================================================\n\n";

    std::filesystem::path targetPath = (argc > 1) ? argv[1] : "./test_samples";

    std::cout << "[*] Scanning target path: " << targetPath << "\n\n";

    ecdat::AstScanner scanner;
    std::vector<ecdat::CryptoAsset> findings;

    if (std::filesystem::is_directory(targetPath)) {
        findings = scanner.scanDirectory(targetPath);
    } else {
        findings = scanner.scanFile(targetPath);
    }

    std::cout << "----------------------------------------------------\n";
    std::cout << "Discovered Cryptographic Assets: " << findings.size() << "\n";
    std::cout << "----------------------------------------------------\n";

    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& asset = findings[i];
        std::cout << "[" << (i + 1) << "] " << asset.algorithm 
                  << " (" << asset.typeString() << ")\n";
        std::cout << "    Location   : " << asset.filePath << ":" << asset.lineNumber.value_or(0) << "\n";
        std::cout << "    Key Size   : " << (asset.keySize.has_value() ? std::to_string(asset.keySize.value()) + " bits" : "N/A") << "\n";
        std::cout << "    Mode       : " << asset.mode.value_or("N/A") << "\n";
        std::cout << "    Risk Level : " << asset.severityString() << "\n";
        std::cout << "    Evidence   : " << asset.evidence << "\n\n";
    }

    return 0;
}