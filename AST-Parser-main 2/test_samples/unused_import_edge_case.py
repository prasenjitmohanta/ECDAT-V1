# ==============================================================================
# Edge Case Test: Unused Imports / Dead Code False Positive Filter
# ==============================================================================
from Crypto.PublicKey import RSA   # <- UNUSED IMPORT (Should NOT produce false positive)
from Crypto.Cipher import DES      # <- UNUSED IMPORT (Should NOT produce false positive)
from Crypto.Cipher import Blowfish # <- UNUSED IMPORT (Should NOT produce false positive)
from Crypto.Cipher import AES      # <- ACTUALLY USED BELOW

def process_payload(payload: bytes, key: bytes):
    # Only AES is genuinely instantiated and used
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt(payload)
