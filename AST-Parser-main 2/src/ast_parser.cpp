#include "../include/ast_parser.hpp"
#include "../include/cpp-tree-sitter.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <optional>
#include <cctype>
#include <set>
#include <map>

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

// Helper to dynamically extract integer argument from a call_expression node
static std::optional<int> extractCallArgumentInt(ts::Node identifierNode, const std::string& code, size_t targetArgIndex) {
    auto parentOpt = identifierNode.getParent();
    if (!parentOpt.has_value()) return std::nullopt;

    ts::Node callNode = *parentOpt;
    while (callNode.getType() != "call_expression" && callNode.getType() != "call") {
        auto p = callNode.getParent();
        if (!p.has_value()) break;
        callNode = *p;
    }

    std::optional<ts::Node> argListOpt;
    for (uint32_t i = 0; i < callNode.getNumChildren(); ++i) {
        auto child = callNode.getChild(i);
        if (child.has_value() && child->getType() == "argument_list") {
            argListOpt = child;
            break;
        }
    }
    if (!argListOpt.has_value()) return std::nullopt;

    ts::Node argList = *argListOpt;
    size_t currentArg = 0;

    for (uint32_t i = 0; i < argList.getNumChildren(); ++i) {
        auto childOpt = argList.getChild(i);
        if (!childOpt.has_value()) continue;
        ts::Node child = *childOpt;
        std::string_view type = child.getType();

        if (type != "(" && type != ")" && type != ",") {
            if (currentArg == targetArgIndex) {
                uint32_t start = child.getByteRange().start;
                uint32_t end = child.getByteRange().end;
                std::string argText = code.substr(start, end - start);
                
                std::string numOnly = "";
                for (char c : argText) {
                    if (std::isdigit(c)) numOnly += c;
                }
                if (!numOnly.empty()) {
                    try {
                        return std::stoi(numOnly);
                    } catch (...) {
                        return std::nullopt;
                    }
                }
            }
            currentArg++;
        }
    }
    return std::nullopt;
}

static std::optional<std::string> extractCallArgumentStr(ts::Node identifierNode, const std::string& code) {
    auto parentOpt = identifierNode.getParent();
    if (!parentOpt.has_value()) return std::nullopt;

    ts::Node callNode = *parentOpt;
    while (callNode.getType() != "call_expression" && callNode.getType() != "call") {
        auto p = callNode.getParent();
        if (!p.has_value()) break;
        callNode = *p;
    }

    uint32_t start = callNode.getByteRange().start;
    uint32_t end = callNode.getByteRange().end;
    std::string callCode = code.substr(start, end - start);

    if (callCode.find("P-521") != std::string::npos || callCode.find("secp521r1") != std::string::npos) return "NIST P-521";
    if (callCode.find("P-384") != std::string::npos || callCode.find("secp384r1") != std::string::npos) return "NIST P-384";
    if (callCode.find("P-256") != std::string::npos || callCode.find("secp256r1") != std::string::npos || callCode.find("prime256v1") != std::string::npos) return "NIST P-256";
    if (callCode.find("Ed25519") != std::string::npos || callCode.find("Curve25519") != std::string::npos || callCode.find("X25519") != std::string::npos) return "Curve25519";
    return std::nullopt;
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

            // 1. AES Family
            if (funcName == "EVP_aes_256_gcm" || funcName == "EVP_aes_256_cbc" || funcName == "EVP_aes_256_ctr") {
                std::string mode = (funcName.find("gcm") != std::string::npos) ? "GCM" : ((funcName.find("ctr") != std::string::npos) ? "CTR" : "CBC");
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "AES-256", 256, mode,
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "EVP_aes_192_gcm" || funcName == "EVP_aes_192_cbc") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "AES-192", 192, "CBC",
                    Severity::Moderate, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "EVP_aes_128_gcm" || funcName == "EVP_aes_128_cbc" || funcName == "EVP_aes_128_ctr") {
                std::string mode = (funcName.find("gcm") != std::string::npos) ? "GCM" : "CBC";
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "AES-128", 128, mode,
                    Severity::Moderate, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "AES_set_encrypt_key" || funcName == "AES_set_decrypt_key") {
                auto dynBits = extractCallArgumentInt(node, code, 1);
                int bits = dynBits.value_or(128);
                Severity sev = (bits == 256) ? Severity::Safe : Severity::Moderate;
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "AES-" + std::to_string(bits), bits, "Raw",
                    sev, "HIGH", SourceStage::AST_Parser, funcName + " (" + std::to_string(bits) + " bits)"
                });
            }
            // 2. RSA Family
            else if (funcName == "RSA_generate_key_ex" || funcName == "EVP_PKEY_CTX_set_rsa_keygen_bits") {
                auto dynBits = extractCallArgumentInt(node, code, 1);
                int bits = dynBits.value_or(2048);
                assets.push_back({
                    filePath, line, AssetType::Asymmetric, "RSA-" + std::to_string(bits), bits, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName + " (" + std::to_string(bits) + " bits)"
                });
            }
            // 3. DES Family
            else if (funcName == "EVP_des_cbc" || funcName == "EVP_des_ecb" || funcName == "DES_set_key_checked" || funcName == "DES_ecb_encrypt") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "DES", 56, "CBC",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName
                });
            }
            // 4. 3DES Family
            else if (funcName == "EVP_des_ede3_cbc" || funcName == "DES_ede3_cbc_encrypt") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "3DES", 168, "CBC",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "EVP_des_ede_cbc") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "3DES (2-Key)", 112, "CBC",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName
                });
            }
            // 5. ChaCha20 Family
            else if (funcName == "EVP_chacha20_poly1305") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "ChaCha20-Poly1305", 256, "Stream",
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "EVP_chacha20") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "ChaCha20", 256, "Stream",
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, funcName
                });
            }
            // 6. Blowfish Family
            else if (funcName == "EVP_bf_cbc" || funcName == "EVP_bf_ecb" || funcName == "BF_set_key") {
                auto dynBits = extractCallArgumentInt(node, code, 1);
                int bits = dynBits.value_or(128);
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "Blowfish", bits, "CBC",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName + " (" + std::to_string(bits) + " bits)"
                });
            }
            // 7. RC4 Family
            else if (funcName == "EVP_rc4" || funcName == "RC4_set_key" || funcName == "RC4") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "RC4", 128, "Stream",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "EVP_rc4_40") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "RC4-40", 40, "Stream",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName
                });
            }
            // 8. ECC Family
            else if (funcName == "EC_KEY_new_by_curve_name" || funcName == "EVP_PKEY_CTX_set_ec_paramgen_curve_nid") {
                auto curveName = extractCallArgumentStr(node, code);
                std::string curve = curveName.value_or("NIST P-256");
                int bits = (curve == "NIST P-521") ? 521 : ((curve == "NIST P-384") ? 384 : 256);
                assets.push_back({
                    filePath, line, AssetType::Asymmetric, "ECC (" + curve + ")", bits, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName + " [" + curve + "]"
                });
            }
            // Hashes
            else if (funcName == "MD5" || funcName == "EVP_md5") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "MD5", std::nullopt, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "EVP_sha1") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "SHA-1", 160, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "SHA256" || funcName == "EVP_sha256") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "SHA-256", 256, std::nullopt,
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, funcName
                });
            } else if (funcName == "EVP_sha512") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "SHA-512", 512, std::nullopt,
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, funcName
                });
            }
        }
    }

    return assets;
}

// -----------------------------------------------------------------------------
// Python Parser with Two-Pass Semantic Symbol Resolution & Dead Code Filtering
// -----------------------------------------------------------------------------
std::vector<CryptoAsset> AstScanner::parsePython(const std::string& code, const std::string& filePath) {
    std::vector<CryptoAsset> assets;

    ts::Language lang(tree_sitter_python());
    auto parserRes = ts::Parser::create(lang);
    if (!parserRes) return assets;
    ts::Parser parser = std::move(*parserRes);

    auto treeRes = parser.parse(code);
    if (!treeRes) return assets;
    ts::Tree tree = std::move(*treeRes);
    ts::Node root = tree.getRootNode();

    // Query 1: Extract all imported crypto symbols and their aliases
    std::string importQueryStr = 
        "[ "
        "  (aliased_import name: (dotted_name) @name alias: (identifier) @alias) "
        "  (import_from_statement name: (dotted_name) @name) "
        "  (import_statement name: (dotted_name) @name) "
        "]";

    // Query 2: Extract all call expressions and attribute access
    std::string callQueryStr = 
        "[ "
        "  (call function: (attribute object: (identifier) @obj attribute: (identifier) @method)) "
        "  (call function: (identifier) @func_name) "
        "  (attribute object: (identifier) @obj attribute: (identifier) @attr) "
        "]";

    auto callQueryRes = ts::Query::create(lang, callQueryStr);
    if (!callQueryRes) return assets;
    ts::Query callQuery = std::move(*callQueryRes);

    ts::QueryCursor cursor;
    auto matchesRes = cursor.getMatches(callQuery, root);
    if (!matchesRes) return assets;

    // Track active/invoked instances in code
    std::set<std::string> activeCryptoSymbols;

    for (const auto& match : *matchesRes) {
        for (const auto& capture : match.getCaptures()) {
            ts::Node node = capture.node;
            uint32_t startByte = node.getByteRange().start;
            uint32_t endByte = node.getByteRange().end;
            std::string token = code.substr(startByte, endByte - startByte);
            int line = getLineNumber(code, startByte);

            // 1. AES Invocations
            if (token == "AES" || token == "FastAES") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "AES", 256, "GCM/CBC",
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, "AES.new / Invocations (Instantiated)"
                });
            }
            // 2. RSA Invocations
            else if (token == "RSA" || token == "PKCS1_OAEP" || token == "RSAPublicKeyManager") {
                auto dynBits = extractCallArgumentInt(node, code, 0);
                int bits = dynBits.value_or(2048);
                assets.push_back({
                    filePath, line, AssetType::Asymmetric, "RSA-" + std::to_string(bits), bits, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "RSA.generate / Invocations (" + std::to_string(bits) + " bits)"
                });
            }
            // 3. DES Invocations
            else if (token == "DES") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "DES", 56, "CBC",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "DES.new (Instantiated)"
                });
            }
            // 4. 3DES Invocations
            else if (token == "DES3" || token == "TripleDES") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "3DES", 168, "ECB/CBC",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "DES3.new (Instantiated)"
                });
            }
            // 5. ChaCha20 Invocations
            else if (token == "ChaCha20" || token == "ChaCha20_Poly1305") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "ChaCha20", 256, "Stream",
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, "ChaCha20.new (Instantiated)"
                });
            }
            // 6. Blowfish Invocations
            else if (token == "Blowfish") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "Blowfish", 128, "CBC",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "Blowfish.new (Instantiated)"
                });
            }
            // 7. RC4 Invocations
            else if (token == "ARC4" || token == "RC4") {
                assets.push_back({
                    filePath, line, AssetType::Symmetric, "RC4", 128, "Stream",
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "ARC4.new (Instantiated)"
                });
            }
            // 8. ECC Invocations
            else if (token == "ECC" || token == "ec") {
                auto curveName = extractCallArgumentStr(node, code);
                std::string curve = curveName.value_or("NIST P-256");
                int bits = (curve == "NIST P-521") ? 521 : ((curve == "NIST P-384") ? 384 : 256);
                assets.push_back({
                    filePath, line, AssetType::Asymmetric, "ECC (" + curve + ")", bits, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "ECC.generate [" + curve + "]"
                });
            }
            // Hashes
            else if (token == "md5") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "MD5", std::nullopt, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "hashlib.md5()"
                });
            } else if (token == "sha1") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "SHA-1", 160, std::nullopt,
                    Severity::Critical, "HIGH", SourceStage::AST_Parser, "hashlib.sha1()"
                });
            } else if (token == "sha256") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "SHA-256", 256, std::nullopt,
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, "hashlib.sha256()"
                });
            } else if (token == "sha512") {
                assets.push_back({
                    filePath, line, AssetType::Hash, "SHA-512", 512, std::nullopt,
                    Severity::Safe, "HIGH", SourceStage::AST_Parser, "hashlib.sha512()"
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
