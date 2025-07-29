import unittest
import sys
import importlib.util
import os

spec = importlib.util.spec_from_file_location("storage", os.path.join(os.path.dirname(__file__), "..", "storage.py"))
if spec is None or spec.loader is None:
    raise ImportError("Could not load storage.py module")
storage = importlib.util.module_from_spec(spec)
sys.modules["storage"] = storage
spec.loader.exec_module(storage)

class TestStorage(unittest.TestCase):
    def test_encode_decode_b64(self):
        data = b"hello"
        encoded = storage.encode_b64(data)
        self.assertIsInstance(encoded, str)
        decoded = storage.decode_b64(encoded)
        self.assertIsInstance(decoded, bytes)

    def test_load_save_vault(self):
        # These are dummies, just check return types
        result = storage.load_vault("vault.json", "password")
        self.assertIsInstance(result, dict)
        self.assertIsNone(storage.save_vault("vault.json", {}, "password"))

if __name__ == "__main__":
    unittest.main()
