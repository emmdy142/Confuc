# tests/test_registry.py
import unittest
from config import ConfigManager
from registry import RegistryChecker

class DummyConfig:
    def __init__(self):
        self.config = {"enable_npm": True}

class TestRegistryChecker(unittest.TestCase):
    def test_check_known(self):
        checker = RegistryChecker(DummyConfig())
        result = checker.check("express")
        self.assertIn("npm_exists", result)

    def test_check_unknown(self):
        checker = RegistryChecker(DummyConfig())
        result = checker.check("thispackagedoesnotexist12345")
        self.assertIn("confusable", result)

if __name__ == "__main__":
    unittest.main()
