/*
===============================================================================
  ECDAT Enterprise Cryptographic Signatures (YARA Rules)
  Comprehensive Detection for 8 Core Algorithms & Distinct Key Sizes
  [AES, RSA, DES, 3DES, ChaCha20, Blowfish, RC4, ECC]
===============================================================================
*/

// --- 1. AES (Advanced Encryption Standard) ---
rule Detect_AES_Forward_SBox {
    meta:
        description = "Compiled AES Rijndael Forward S-Box table"
        algorithm = "AES"
        asset_type = "Symmetric"
        key_size = 256
        severity = "SAFE"
    strings:
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        $aes_sbox
}

rule Detect_AES_Inverse_SBox {
    meta:
        description = "Compiled AES Inverted S-Box table (Decryption routine)"
        algorithm = "AES"
        asset_type = "Symmetric"
        key_size = 256
        severity = "SAFE"
    strings:
        $aes_inv_sbox = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
    condition:
        $aes_inv_sbox
}

// --- 2. RSA (Rivest-Shamir-Adleman) ---
rule Detect_RSA_DER_Key_Header {
    meta:
        description = "ASN.1 DER / PKCS#1 RSA Private Key Sequence Magic Header"
        algorithm = "RSA-2048"
        asset_type = "Asymmetric"
        key_size = 2048
        severity = "CRITICAL"
    strings:
        // PKCS#1 ASN.1 Sequence header for RSA 2048-bit keys
        $rsa_der = { 30 82 04 ?? 02 01 00 02 82 01 01 00 }
        $rsa_pem_tag = "BEGIN RSA PRIVATE KEY" ascii
    condition:
        any of them
}

rule Detect_RSA_1024_Marker {
    meta:
        description = "RSA 1024-bit ASN.1 Structure / OpenSSL Marker"
        algorithm = "RSA-1024"
        asset_type = "Asymmetric"
        key_size = 1024
        severity = "CRITICAL"
    strings:
        $rsa1024_der = { 30 82 02 ?? 02 01 00 02 81 81 00 }
    condition:
        $rsa1024_der
}

rule Detect_RSA_4096_Marker {
    meta:
        description = "RSA 4096-bit ASN.1 Structure Header"
        algorithm = "RSA-4096"
        asset_type = "Asymmetric"
        key_size = 4096
        severity = "CRITICAL"
    strings:
        $rsa4096_der = { 30 82 08 ?? 02 01 00 02 82 02 01 00 }
    condition:
        $rsa4096_der
}

// --- 3. DES (Data Encryption Standard) ---
rule Detect_DES_SBox_Permutation {
    meta:
        description = "Compiled DES S-Box 1 & Initial Permutation (IP) table"
        algorithm = "DES"
        asset_type = "Symmetric"
        key_size = 56
        severity = "CRITICAL"
    strings:
        // DES S-Box 1 table entries
        $des_sbox1 = { 0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07 }
    condition:
        $des_sbox1
}

// --- 4. 3DES (Triple DES) ---
rule Detect_3DES_Permutation {
    meta:
        description = "Compiled DES-EDE3 / 3DES Initial Permutation (IP) Table"
        algorithm = "3DES"
        asset_type = "Symmetric"
        key_size = 168
        severity = "CRITICAL"
    strings:
        $des_ip = { 3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04 }
    condition:
        $des_ip
}

// --- 5. ChaCha20 / ChaCha20-Poly1305 ---
rule Detect_ChaCha20_32Byte_Constant {
    meta:
        description = "Compiled ChaCha20 256-bit Key Constant (expand 32-byte k)"
        algorithm = "ChaCha20-Poly1305"
        asset_type = "Symmetric"
        key_size = 256
        severity = "SAFE"
    strings:
        $chacha_const32 = "expand 32-byte k" ascii
    condition:
        $chacha_const32
}

rule Detect_ChaCha20_16Byte_Constant {
    meta:
        description = "Compiled ChaCha20 128-bit Key Constant (expand 16-byte k)"
        algorithm = "ChaCha20"
        asset_type = "Symmetric"
        key_size = 128
        severity = "SAFE"
    strings:
        $chacha_const16 = "expand 16-byte k" ascii
    condition:
        $chacha_const16
}

// --- 6. Blowfish ---
rule Detect_Blowfish_Pi_Constants {
    meta:
        description = "Compiled Blowfish P-array & S-Box Pi fractional constant (243F6A88...)"
        algorithm = "Blowfish"
        asset_type = "Symmetric"
        key_size = 128
        severity = "CRITICAL"
    strings:
        // First 16 bytes of Blowfish P-array initialization (hex representation of Pi digits)
        $bf_pi = { 24 3F 6A 88 85 A3 08 D3 13 19 8A 2E 03 70 73 44 }
    condition:
        $bf_pi
}

// --- 7. RC4 (Rivest Cipher 4 / ARC4) ---
rule Detect_RC4_KSA_Permutation {
    meta:
        description = "RC4 Key Scheduling Algorithm (KSA) 256-byte State Initializer"
        algorithm = "RC4"
        asset_type = "Symmetric"
        key_size = 128
        severity = "CRITICAL"
    strings:
        // Assembly loop idiom for RC4 S[i] = i initialization (x86 / x64 byte loop)
        $rc4_init = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }
        $rc4_str  = "RC4_set_key" ascii
    condition:
        any of them
}

// --- 8. ECC (Elliptic Curve Cryptography) ---
rule Detect_ECC_NIST_P256_Prime {
    meta:
        description = "NIST P-256 (secp256r1) Field Modulus Prime Constant"
        algorithm = "ECC (NIST P-256)"
        asset_type = "Asymmetric"
        key_size = 256
        severity = "CRITICAL"
    strings:
        // NIST P-256 Prime: 2^256 - 2^224 + 2^192 + 2^96 - 1 (big-endian / little-endian representations)
        $p256_be = { FF FF FF FF 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF }
        $secp256k1_str = "secp256r1" ascii
    condition:
        any of them
}

rule Detect_ECC_NIST_P384_Prime {
    meta:
        description = "NIST P-384 (secp384r1) Field Modulus Prime Constant"
        algorithm = "ECC (NIST P-384)"
        asset_type = "Asymmetric"
        key_size = 384
        severity = "CRITICAL"
    strings:
        // NIST P-384 Prime: 2^384 - 2^128 - 2^96 + 2^32 - 1
        $p384_str = "secp384r1" ascii
        $p384_prime = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE FF FF FF FF 00 00 00 00 00 00 00 00 FF FF FF FF }
    condition:
        any of them
}

rule Detect_ECC_NIST_P521_Prime {
    meta:
        description = "NIST P-521 (secp521r1) 521-bit Field Modulus Constant"
        algorithm = "ECC (NIST P-521)"
        asset_type = "Asymmetric"
        key_size = 521
        severity = "CRITICAL"
    strings:
        $p521_str = "secp521r1" ascii
        $p521_nid = "NID_secp521r1" ascii
    condition:
        any of them
}

rule Detect_ECC_Curve25519 {
    meta:
        description = "Curve25519 / Ed25519 Prime Field Constant (2^255 - 19)"
        algorithm = "ECC (Curve25519)"
        asset_type = "Asymmetric"
        key_size = 256
        severity = "CRITICAL"
    strings:
        $c25519_prime = { ED FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 7F }
        $c25519_str = "Curve25519" ascii
        $ed25519_str = "Ed25519" ascii
    condition:
        any of them
}

// --- Auxiliary Hashes ---
rule Detect_SHA256_Constants {
    meta:
        description = "SHA-256 fractional cube root constants"
        algorithm = "SHA-256"
        asset_type = "Hash"
        key_size = 256
        severity = "SAFE"
    strings:
        $sha256_k = { 98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 31 6C 39 }
    condition:
        $sha256_k
}

rule Detect_SHA512_Constants {
    meta:
        description = "SHA-512 64-bit constant words"
        algorithm = "SHA-512"
        asset_type = "Hash"
        key_size = 512
        severity = "SAFE"
    strings:
        $sha512_k = { 28 AE D2 A7 D8 F1 49 42 AF 88 71 54 9B 44 77 71 }
    condition:
        $sha512_k
}
