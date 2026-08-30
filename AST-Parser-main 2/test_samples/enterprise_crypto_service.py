"""
===============================================================================
Enterprise Cryptographic Microservice - AST Edge-Case Test Suite (Python)
===============================================================================
Comprehensive test suite containing PyCryptodome, cryptography.hazmat,
hashlib, aliased imports, multi-line decorators, and quantum edge cases.
"""

import os
import sys
import time
import json
import base64
from typing import Dict, Any, Optional, Tuple

# -----------------------------------------------------------------------------
# EDGE CASE 1: Aliased and Renamed Imports
# -----------------------------------------------------------------------------
from Crypto.Cipher import (
    AES as FastAESEngine,
    DES3 as TripleDESLegacyEngine,
    DES as SingleDESEngine,
    Blowfish as BlowfishLegacy,
    ARC4 as RC4StreamCipher,
    ChaCha20 as ChaCha20Modern
)
from Crypto.PublicKey import RSA as RSAPublicKeyManager, ECC as EllipticCurveManager
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

import hashlib as GlobalHashEngine
from hashlib import (
    md5 as InsecureMD5Hash,
    sha1 as LegacySHA1Hash,
    sha256 as SecureSHA256Hash,
    sha512 as HighSecuritySHA512Hash
)

# -----------------------------------------------------------------------------
# EDGE CASE 2: Comments and String Literals (False Positive Traps)
# -----------------------------------------------------------------------------
# Developer Note: Never use MD5, DES3 or RSA-1024 in modern production!
# Reference: AES.MODE_ECB is dangerous because identical blocks yield identical ciphertext.
SYSTEM_LOG_TEMPLATE = "AUDIT_EVENT: Detected cipher initialization using AES-128 and DES"
INSECURE_ALGO_LIST = ["MD5", "SHA1", "DES", "3DES", "RC4"]


class SecurityAuditConfig:
    DEFAULT_DATA_LIFETIME_YEARS: int = 15
    PQC_MIGRATION_WINDOW_YEARS: int = 3
    CRQC_QUANTUM_ARRIVAL_YEARS: int = 10


# -----------------------------------------------------------------------------
# MODULE 1: Modern Quantum-Resistant Symmetric Handlers (AES-256 GCM / CBC)
# -----------------------------------------------------------------------------
class ModernEncryptionService:
    """Provides modern 256-bit symmetric encryption."""

    def __init__(self, key_256: Optional[bytes] = None):
        # 32 bytes = 256-bit key (Quantum Safe)
        self.key = key_256 or get_random_bytes(32)

    # EDGE CASE 3: Multi-line Call with named parameters
    def encrypt_aes_gcm(self, plaintext: bytes) -> Dict[str, bytes]:
        """Encrypts data using AES-256 in GCM authenticated mode."""
        cipher = FastAESEngine.new(
            self.key,
            FastAESEngine.MODE_GCM
        )
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return {
            "nonce": cipher.nonce,
            "ciphertext": ciphertext,
            "tag": tag,
            "algorithm": "AES-256-GCM",
            "security": "QUANTUM_SAFE"
        }

    def encrypt_aes_cbc(self, plaintext: bytes) -> Dict[str, bytes]:
        """Encrypts data using AES-256 in CBC mode with PKCS7 padding."""
        iv = get_random_bytes(16)
        cipher = FastAESEngine.new(
            self.key,
            FastAESEngine.MODE_CBC,
            iv=iv
        )
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)
        ciphertext = cipher.encrypt(padded)
        return {
            "iv": iv,
            "ciphertext": ciphertext,
            "algorithm": "AES-256-CBC"
        }

    def encrypt_chacha20(self, plaintext: bytes) -> Dict[str, bytes]:
        """Encrypts data using modern ChaCha20 stream cipher."""
        cipher = ChaCha20Modern.new(key=self.key)
        ciphertext = cipher.encrypt(plaintext)
        return {
            "nonce": cipher.nonce,
            "ciphertext": ciphertext,
            "algorithm": "ChaCha20"
        }


# -----------------------------------------------------------------------------
# MODULE 2: Broken & Insecure Symmetric Ciphers (AES-ECB, 3DES, DES, Blowfish)
# -----------------------------------------------------------------------------
class InsecureLegacyCipherService:
    """Handles legacy decryption for backward compatibility (HIGH VULNERABILITY)."""

    def __init__(self):
        # 16 bytes = 128-bit key (Quantum Weakened by Grover)
        self.weak_key_128 = get_random_bytes(16)
        # 24 bytes = 3DES key
        self.des3_key = get_random_bytes(24)
        # 8 bytes = Single DES key (Classically Broken)
        self.des_key = get_random_bytes(8)
        # Blowfish key
        self.blowfish_key = get_random_bytes(16)

    # EDGE CASE 4: Dangerous ECB Mode Detection
    def insecure_aes_ecb(self, plaintext: bytes) -> bytes:
        """Insecure AES in Electronic Codebook Mode (Leaks data patterns)."""
        cipher = FastAESEngine.new(
            self.weak_key_128,
            FastAESEngine.MODE_ECB
        )
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)
        return cipher.encrypt(padded)

    def insecure_3des_ecb(self, plaintext: bytes) -> bytes:
        """Insecure Triple-DES (Sweet32 vulnerability & Grover weakened)."""
        cipher = TripleDESLegacyEngine.new(
            self.des3_key,
            TripleDESLegacyEngine.MODE_ECB
        )
        pad_len = 8 - (len(plaintext) % 8)
        padded = plaintext + bytes([pad_len] * pad_len)
        return cipher.encrypt(padded)

    def insecure_single_des(self, plaintext: bytes) -> bytes:
        """Single 56-bit DES (Broken in 1999)."""
        cipher = SingleDESEngine.new(
            self.des_key,
            SingleDESEngine.MODE_CBC,
            iv=b"12345678"
        )
        pad_len = 8 - (len(plaintext) % 8)
        padded = plaintext + bytes([pad_len] * pad_len)
        return cipher.encrypt(padded)

    def legacy_blowfish(self, plaintext: bytes) -> bytes:
        """Legacy 64-bit Blowfish block cipher."""
        cipher = BlowfishLegacy.new(
            self.blowfish_key,
            BlowfishLegacy.MODE_CBC,
            iv=b"abcdefgh"
        )
        pad_len = 8 - (len(plaintext) % 8)
        padded = plaintext + bytes([pad_len] * pad_len)
        return cipher.encrypt(padded)

    def broken_rc4_stream(self, plaintext: bytes) -> bytes:
        """Broken RC4 / ARC4 stream cipher."""
        cipher = RC4StreamCipher.new(b"secret_key_12345")
        return cipher.encrypt(plaintext)


# -----------------------------------------------------------------------------
# MODULE 3: Quantum-Vulnerable Asymmetric Keys (RSA-1024, 2048, 4096, ECC)
# -----------------------------------------------------------------------------
class AsymmetricKeyManager:
    """Manages RSA and Elliptic Curve key pairs (Broken by Shor's Algorithm)."""

    @staticmethod
    def generate_rsa_key_pair(bits: int = 2048):
        """Generates RSA key pair (1024, 2048, 4096 bits)."""
        print(f"[*] Generating RSA Key with {bits} bits...")
        if bits == 1024:
            # Extreme Risk (Classically factorable)
            key = RSAPublicKeyManager.generate(1024)
        elif bits == 2048:
            # Standard RSA (Quantum Broken by Shor)
            key = RSAPublicKeyManager.generate(2048)
        elif bits == 4096:
            # High-Security RSA (Still Quantum Broken)
            key = RSAPublicKeyManager.generate(4096)
        else:
            key = RSAPublicKeyManager.generate(bits)

        private_pem = key.export_key()
        public_pem = key.publickey().export_key()
        return private_pem, public_pem

    @staticmethod
    def generate_ecc_curve():
        """Generates Elliptic Curve key on NIST P-256 curve (Broken by Shor)."""
        key = EllipticCurveManager.generate(curve="P-256")
        return key


# -----------------------------------------------------------------------------
# MODULE 4: Cryptographic Hashing Dispatcher (MD5, SHA1, SHA256, SHA512)
# -----------------------------------------------------------------------------
class IntegrityDigestService:
    """Computes cryptographic hashes across classical and quantum-safe standards."""

    @staticmethod
    def hash_md5_insecure(data: bytes) -> str:
        """Insecure MD5 hash (Collision vulnerable)."""
        h = InsecureMD5Hash()
        h.update(data)
        return h.hexdigest()

    @staticmethod
    def hash_sha1_legacy(data: bytes) -> str:
        """Insecure SHA-1 hash (SHAttered attack)."""
        h = LegacySHA1Hash()
        h.update(data)
        return h.hexdigest()

    @staticmethod
    def hash_sha256_secure(data: bytes) -> str:
        """Quantum-Safe SHA-256."""
        h = SecureSHA256Hash()
        h.update(data)
        return h.hexdigest()

    @staticmethod
    def hash_sha512_maximum(data: bytes) -> str:
        """High-entropy SHA-512."""
        h = HighSecuritySHA512Hash()
        h.update(data)
        return h.hexdigest()

    @staticmethod
    def generic_hashlib_calls(data: bytes):
        """Standard hashlib attribute calls."""
        d1 = GlobalHashEngine.md5(data).hexdigest()
        d2 = GlobalHashEngine.sha1(data).hexdigest()
        d3 = GlobalHashEngine.sha256(data).hexdigest()
        d4 = GlobalHashEngine.sha512(data).hexdigest()
        return d1, d2, d3, d4


# -----------------------------------------------------------------------------
# MODULE 5: Master Orchestrator Pipeline
# -----------------------------------------------------------------------------
class EnterpriseSecurityPipeline:
    """Main orchestration service running cryptographic workflows."""

    def __init__(self):
        self.modern = ModernEncryptionService()
        self.legacy = InsecureLegacyCipherService()
        self.asymmetric = AsymmetricKeyManager()
        self.digest = IntegrityDigestService()

    def run_full_suite(self):
        print("=" * 60)
        print("  Starting Enterprise Security Cryptographic Execution")
        print("=" * 60)

        test_payload = b"TopSecretEnterprisePayloadForSecurityAudit2026"

        # 1. Modern AES-256 & ChaCha20
        gcm_res = self.modern.encrypt_aes_gcm(test_payload)
        cbc_res = self.modern.encrypt_aes_cbc(test_payload)
        chacha_res = self.modern.encrypt_chacha20(test_payload)

        # 2. Insecure Legacy Ciphers
        ecb_res = self.legacy.insecure_aes_ecb(test_payload)
        des3_res = self.legacy.insecure_3des_ecb(test_payload)
        des_res = self.legacy.insecure_single_des(test_payload)
        blowfish_res = self.legacy.legacy_blowfish(test_payload)
        rc4_res = self.legacy.broken_rc4_stream(test_payload)

        # 3. Asymmetric Key Operations
        rsa_1024_priv, _ = self.asymmetric.generate_rsa_key_pair(1024)
        rsa_2048_priv, _ = self.asymmetric.generate_rsa_key_pair(2048)
        rsa_4096_priv, _ = self.asymmetric.generate_rsa_key_pair(4096)
        ecc_key = self.asymmetric.generate_ecc_curve()

        # 4. Hash Integrity Checksums
        h_md5 = self.digest.hash_md5_insecure(test_payload)
        h_sha1 = self.digest.hash_sha1_legacy(test_payload)
        h_sha256 = self.digest.hash_sha256_secure(test_payload)
        h_sha512 = self.digest.hash_sha512_maximum(test_payload)

        print("[+] All Cryptographic Workflows Initialized Successfully.")


if __name__ == "__main__":
    pipeline = EnterpriseSecurityPipeline()
    pipeline.run_full_suite()
