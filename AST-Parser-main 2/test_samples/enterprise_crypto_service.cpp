/**
 * ============================================================================
 * Enterprise Cryptographic Service - Edge-Case Test Suite (C++20)
 * ============================================================================
 * Contains realistic enterprise security routines, legacy authentication,
 * OpenSSL EVP wrappers, key exchange protocols, and AST parsing edge cases.
 */

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <chrono>
#include <thread>
#include <map>

// OpenSSL Header Inclusions
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

namespace enterprise::security {

// ----------------------------------------------------------------------------
// EDGE CASE 1: False Positive Traps in Comments & String Literals
// AST parsers MUST ignore these comments and plain strings!
// ----------------------------------------------------------------------------
// Insecure legacy note: Developers should avoid using MD5 and DES3 in production!
// Reference: RSA_generate_key_ex is deprecated in OpenSSL 3.0 in favor of EVP_PKEY.
const std::string AUDIT_LOG_HEADER = "CRITICAL_AUDIT: AES-128 and DES verification module initialized.";
const std::string MD5_WARNING_BANNER = "WARNING: System detected legacy MD5 signature from client request.";

enum class SecurityLevel {
    LEGACY_COMPATIBILITY,
    COMMERCIAL_STANDARD,
    POST_QUANTUM_READY
};

struct CipherSession {
    std::string sessionId;
    uint32_t keyLength;
    std::string algorithmName;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> sessionKey;
    bool isAuthenticated;
};

// ----------------------------------------------------------------------------
// MODULE 1: Modern Quantum-Resistant Symmetric Encryption (AES-256-GCM)
// ----------------------------------------------------------------------------
class ModernDataEncryptor {
public:
    ModernDataEncryptor() : ctx_(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free) {}

    // EDGE CASE 2: Multi-line nested call expression
    bool encryptPayloadGCM(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        std::vector<uint8_t>& ciphertext,
        std::vector<uint8_t>& tag
    ) {
        if (key.size() != 32 || iv.size() != 12) {
            return false;
        }

        int len = 0;
        int ciphertext_len = 0;
        ciphertext.resize(plaintext.size());
        tag.resize(16);

        // AST Target: EVP_aes_256_gcm()
        if (1 != EVP_EncryptInit_ex(
                     ctx_.get(),
                     EVP_aes_256_gcm(),
                     nullptr,
                     nullptr,
                     nullptr
                 )) {
            return false;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr)) {
            return false;
        }

        if (1 != EVP_EncryptInit_ex(ctx_.get(), nullptr, nullptr, key.data(), iv.data())) {
            return false;
        }

        if (1 != EVP_EncryptUpdate(ctx_.get(), ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size()))) {
            return false;
        }
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx_.get(), ciphertext.data() + len, &len)) {
            return false;
        }
        ciphertext_len += len;

        EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        ciphertext.resize(ciphertext_len);
        return true;
    }

    // AST Target: ChaCha20-Poly1305 Modern Stream Cipher
    bool encryptChaCha20(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        std::vector<uint8_t>& ciphertext
    ) {
        int len = 0;
        ciphertext.resize(plaintext.size() + 16);

        if (1 != EVP_EncryptInit_ex(
                     ctx_.get(),
                     EVP_chacha20_poly1305(),
                     nullptr,
                     key.data(),
                     nonce.data()
                 )) {
            return false;
        }

        EVP_EncryptUpdate(ctx_.get(), ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size()));
        EVP_EncryptFinal_ex(ctx_.get(), ciphertext.data() + len, &len);
        return true;
    }

private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_;
};

// ----------------------------------------------------------------------------
// MODULE 2: Legacy Quantum-Vulnerable Asymmetric Key Generation (RSA-1024, 2048, 4096)
// ----------------------------------------------------------------------------
class LegacyKeyManager {
public:
    // EDGE CASE 3: Parameter inspection for variable key sizes (1024 vs 2048 vs 4096)
    static bool generateLegacyRSAKey(int keyBits) {
        std::cout << "[*] Initializing RSA Key Generation for bits: " << keyBits << "\n";
        
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);

        RSA* rsa = RSA_new();
        
        // AST Target: RSA_generate_key_ex with dynamic bits parameter
        if (keyBits == 1024) {
            // High vulnerability legacy key
            RSA_generate_key_ex(rsa, 1024, bn, nullptr);
        } else if (keyBits == 2048) {
            // Standard commercial RSA key (Quantum Broken)
            RSA_generate_key_ex(rsa, 2048, bn, nullptr);
        } else if (keyBits == 4096) {
            // Extended RSA key (Still Quantum Broken by Shor)
            RSA_generate_key_ex(rsa, 4096, bn, nullptr);
        }

        RSA_free(rsa);
        BN_free(bn);
        return true;
    }

    // AST Target: Elliptic Curve Key Generation (ECC Curve P-256)
    static bool generateEllipticCurveKey() {
        // Quantum Vulnerable ECC (Broken by Shor)
        EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (ecKey) {
            EC_KEY_generate_key(ecKey);
            EC_KEY_free(ecKey);
            return true;
        }
        return false;
    }
};

// ----------------------------------------------------------------------------
// MODULE 3: Weak & Broken Legacy Ciphers (3DES-CBC, DES-ECB, AES-128-CBC)
// ----------------------------------------------------------------------------
class LegacySymmetricFallback {
public:
    // AST Target: Insecure 3DES Block Cipher
    static void legacy3DESEncryption(const uint8_t* in, uint8_t* out, size_t length, const uint8_t* key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        
        // Insecure 3DES call (Grover weakened & Sweet32 birthday collision attack)
        EVP_EncryptInit_ex(
            ctx,
            EVP_des_ede3_cbc(),
            nullptr,
            key,
            nullptr
        );
        
        int outlen = 0;
        EVP_EncryptUpdate(ctx, out, &outlen, in, static_cast<int>(length));
        EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
        EVP_CIPHER_CTX_free(ctx);
    }

    // AST Target: Weak AES-128-CBC (Quantum Weakened)
    static void weakAES128CBC(const uint8_t* input, uint8_t* output, int len, const uint8_t* k, const uint8_t* iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        
        EVP_EncryptInit_ex(
            ctx,
            EVP_aes_128_cbc(),
            nullptr,
            k,
            iv
        );

        int outlen = 0;
        EVP_EncryptUpdate(ctx, output, &outlen, input, len);
        EVP_EncryptFinal_ex(ctx, output + outlen, &outlen);
        EVP_CIPHER_CTX_free(ctx);
    }

    // AST Target: Low-level AES_set_encrypt_key
    static void lowLevelAESRaw(const unsigned char* userKey, AES_KEY* key) {
        AES_set_encrypt_key(userKey, 128, key);
    }
};

// ----------------------------------------------------------------------------
// MODULE 4: Cryptographic Hashing Engine (MD5, SHA-1, SHA-256, SHA-512)
// ----------------------------------------------------------------------------
class IntegrityVerifier {
public:
    // AST Target: Insecure MD5 Hash
    static void computeMD5(const std::string& input, unsigned char* digest) {
        // Broken by classical collision attacks
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr);
        EVP_DigestUpdate(mdctx, input.c_str(), input.length());
        EVP_DigestFinal_ex(mdctx, digest, nullptr);
        EVP_MD_CTX_free(mdctx);
    }

    // AST Target: Insecure SHA-1 Hash
    static void computeSHA1(const std::string& input, unsigned char* digest) {
        // Broken by SHAttered collision attack
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha1(), nullptr);
        EVP_DigestUpdate(mdctx, input.c_str(), input.length());
        EVP_DigestFinal_ex(mdctx, digest, nullptr);
        EVP_MD_CTX_free(mdctx);
    }

    // AST Target: Secure SHA-256 (Quantum Resistant)
    static void computeSHA256(const std::string& input, unsigned char* digest) {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, input.c_str(), input.length());
        EVP_DigestFinal_ex(mdctx, digest, nullptr);
        EVP_MD_CTX_free(mdctx);
    }

    // AST Target: High-Security SHA-512
    static void computeSHA512(const std::string& input, unsigned char* digest) {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr);
        EVP_DigestUpdate(mdctx, input.c_str(), input.length());
        EVP_DigestFinal_ex(mdctx, digest, nullptr);
        EVP_MD_CTX_free(mdctx);
    }
};

// ----------------------------------------------------------------------------
// MODULE 5: Master Orchestration Dispatcher
// ----------------------------------------------------------------------------
class EnterpriseCryptoService {
public:
    EnterpriseCryptoService() : encryptor_(std::make_unique<ModernDataEncryptor>()) {}

    void executeFullSecurityAudit() {
        std::cout << "[+] Running Enterprise Cryptographic Security Audit...\n";

        // Trigger RSA routines
        LegacyKeyManager::generateLegacyRSAKey(1024);
        LegacyKeyManager::generateLegacyRSAKey(2048);
        LegacyKeyManager::generateLegacyRSAKey(4096);
        LegacyKeyManager::generateEllipticCurveKey();

        // Trigger Hash routines
        unsigned char md5_buf[16];
        unsigned char sha1_buf[20];
        unsigned char sha256_buf[32];
        unsigned char sha512_buf[64];
        IntegrityVerifier::computeMD5("secret_auth_token", md5_buf);
        IntegrityVerifier::computeSHA1("session_handshake", sha1_buf);
        IntegrityVerifier::computeSHA256("secure_transaction", sha256_buf);
        IntegrityVerifier::computeSHA512("admin_master_credential", sha512_buf);

        // Trigger AES and 3DES routines
        std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> key256(32, 0x42);
        std::vector<uint8_t> iv12(12, 0x01);
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag;

        encryptor_->encryptPayloadGCM(payload, key256, iv12, ciphertext, tag);

        uint8_t des_out[64];
        uint8_t des_key[24] = {0};
        LegacySymmetricFallback::legacy3DESEncryption(payload.data(), des_out, payload.size(), des_key);

        std::cout << "[+] Enterprise Cryptographic Audit Completed.\n";
    }

private:
    std::unique_ptr<ModernDataEncryptor> encryptor_;
};

} // namespace enterprise::security

// Entry Point Test Wrapper
int main() {
    enterprise::security::EnterpriseCryptoService service;
    service.executeFullSecurityAudit();
    return 0;
}
