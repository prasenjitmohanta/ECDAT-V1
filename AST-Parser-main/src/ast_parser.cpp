#include "../include/ast_parser.hpp"
#include "../include/cpp-tree-sitter.h"
#include <fstream>
#include <sstream>
#include <iostream>

struct TSLanguage;
extern "C" const TSLanguage* tree_sitter_cpp();
extern "C" const TSLanguage* tree_sitter_python();

namespace ecdat {

AstScanner::AstScanner() {}
AstScanner::~AstScanner() {}

int AstScanner::getLineNumber(const std::string& code, size_t byteOffset) {
    int line = 1;
    for (size_t i = 0; i < byteOffset && i < code.size(); ++i) {
        if (code[i] == '\n') {
            line++;
        }
    }
    return line;
}

std::vector<CryptoAsset> AstScanner::scanFile(const std::filesystem::path& filePath) {
    std::vector<CryptoAsset> findings;

    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        return findings;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string code = buffer.str();

    std::string ext = filePath.extension().string();
    if (ext == ".cpp" || ext == ".c" || ext == ".h" || ext == ".hpp" || ext == ".cc") {
        return parseCpp(code, filePath.string());
    } else if (ext == ".py") {
        return parsePython(code, filePath.string());
    }

    return findings;
}

std::vector<CryptoAsset> AstScanner::parseCpp(const std::string& code, const std::string& filePath) {
    std::vector<CryptoAsset> assets;

    ts::Language lang(tree_sitter_cpp());
    auto parserRes = ts::Parser::create(lang);
    if (!parserRes) return assets;
    ts::Parser parser = std::move(*parserRes);

    auto treeRes = parser.parse(code);
    if (!treeRes) return assets;
    ts::Tree tree = std::move(*treeRes);
    ts::Node root = tree.getRootNode();

    std::string queryStr = 
        "(call_expression "
        "  function: (identifier) @func_name) @call";

    auto queryRes = ts::Query::create(lang, queryStr);
    if (!queryRes) return assets;
    ts::Query query = std::move(*queryRes);

    ts::QueryCursor cursor;
    auto matchesRes = cursor.getMatches(query, root);
    if (!matchesRes) return assets;

    for (const auto& match : *matchesRes) {
        for (const auto& capture : match.getCaptures()) {
            ts::Node node = capture.node;
            uint32_t startByte = node.getByteRange().start;
            uint32_t endByte = node.getByteRange().end;

            std::string funcName = code.substr(startByte, endByte - startByte);
            int line = getLineNumber(code, startByte);

            if (funcName == "EVP_aes_256_gcm" || funcName == "EVP_aes_256_cbc") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "AES-256", 256,
                    funcName.find("gcm") != std::string::npos ? "GCM" : "CBC",
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "EVP_aes_128_cbc" || funcName == "AES_set_encrypt_key") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "AES-128", 128, "CBC",
                    Severity::Moderate, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "RSA_generate_key_ex" || funcName == "EVP_PKEY_CTX_new_id") {
                assets.push_back({
                    filePath, line, AssetType::Asymmetric, "RSA", 2048, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "MD5" || funcName == "EVP_md5") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "MD5", std::nullopt, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "SHA256" || funcName == "EVP_sha256") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "SHA-256", 256, std::nullopt,
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, funcName
                });
            }
        }
    }

    return assets;
}

std::vector<CryptoAsset> AstScanner::parsePython(const std::string& code, const std::string& filePath) {
    std::vector<CryptoAsset> assets;

    // Use Python grammar here
    ts::Language lang(tree_sitter_python());
    auto parserRes = ts::Parser::create(lang);
    if (!parserRes) return assets;
    ts::Parser parser = std::move(*parserRes);

    auto treeRes = parser.parse(code);
    if (!treeRes) return assets;
    ts::Tree tree = std::move(*treeRes);
    ts::Node root = tree.getRootNode();

    // Query Python imports
    std::string queryStr = 
        "(import_from_statement "
        "  module_name: (dotted_name) @module "
        "  name: (dotted_name) @imported_name) @import";

    auto queryRes = ts::Query::create(lang, queryStr);
    if (!queryRes) return assets;
    ts::Query query = std::move(*queryRes);

    ts::QueryCursor cursor;
    auto matchesRes = cursor.getMatches(query, root);
    if (!matchesRes) return assets;

    for (const auto& match : *matchesRes) {
        for (const auto& capture : match.getCaptures()) {
            ts::Node node = capture.node;
            uint32_t startByte = node.getByteRange().start;
            uint32_t endByte = node.getByteRange().end;
            std::string token = code.substr(startByte, endByte - startByte);
            int line = getLineNumber(code, startByte);

            if (token == "AES") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "AES", 256, std::nullopt,
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, "from Crypto.Cipher import AES"
                });
            } else if (token == "DES3" || token == "DES") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, token, 64, "ECB",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "from Crypto.Cipher import " + token
                });
            } else if (token == "RSA") {
                assets.push_back({
                    filePath, line, AssetType::Asymmetric, "RSA", 2048, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "from Crypto.PublicKey import RSA"
                });
            } else if (token == "md5") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "MD5", std::nullopt, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "from hashlib import md5"
                });
            }
        }
    }

    return assets;
}

std::vector<CryptoAsset> AstScanner::scanDirectory(const std::filesystem::path& dirPath) {
    std::vector<CryptoAsset> allAssets;
    if (!std::filesystem::exists(dirPath)) return allAssets;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath)) {
        if (entry.is_regular_file()) {
            auto fileAssets = scanFile(entry.path());
            allAssets.insert(allAssets.end(), fileAssets.begin(), fileAssets.end());
        }
    }
    return allAssets;
}

} // namespace ecdat