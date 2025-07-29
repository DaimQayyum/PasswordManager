import unittest
import sys
import importlib.util
import os

spec = importlib.util.spec_from_file_location("crypto", os.path.join(os.path.dirname(__file__), "..", "crypto.py"))
if spec is None or spec.loader is None:
    raise ImportError("Could not load crypto.py module")
crypto = importlib.util.module_from_spec(spec)
sys.modules["crypto"] = crypto
spec.loader.exec_module(crypto)

class TestCrypto(unittest.TestCase):
    def test_derive_key(self):
        key, salt = crypto.derive_key("password")
        self.assertIsInstance(key, bytes)
        self.assertIsInstance(salt, bytes)

    def test_encrypt_decrypt(self):
        key, _ = crypto.derive_key("password")
        plaintext = b"secret"
        ciphertext, nonce, tag = crypto.encrypt(plaintext, key)
        self.assertIsInstance(ciphertext, bytes)
        self.assertIsInstance(nonce, bytes)
        self.assertIsInstance(tag, bytes)
        decrypted = crypto.decrypt(ciphertext, key, nonce, tag)
        self.assertIsInstance(decrypted, bytes)

if __name__ == "__main__":
    unittest.main()
