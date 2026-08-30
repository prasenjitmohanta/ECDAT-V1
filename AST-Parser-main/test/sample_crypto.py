from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA
from hashlib import md5

def setup_encryption():
    key = b"12345678901234567890123456789012"
    cipher = AES.new(key, AES.MODE_CBC)
    legacy = DES3.new(b"1234567812345678")
    h = md5()