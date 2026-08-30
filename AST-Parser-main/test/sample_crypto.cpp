#include <iostream>
#include <openssl/evp.h>
#include <openssl/rsa.h>

void initializeSecurity() {
    // Quantum Safe AES-256
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    // Quantum Vulnerable Legacy RSA
    RSA_generate_key_ex(NULL, 2048, NULL, NULL);

    // Insecure Legacy Hash
    EVP_md5();
}