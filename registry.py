# registry.py
# Registry checker for dependency confusion testing

import requests

class RegistryChecker:
    def __init__(self, config):
        self.config = config

    def check(self, dep_name):
        result = {}
        if self.config.config.get("enable_npm", True):
            npm_url = f"https://registry.npmjs.org/{dep_name}"
            try:
                resp = requests.get(npm_url, timeout=3)
                result["npm_exists"] = resp.status_code == 200
            except Exception:
                result["npm_exists"] = False
        result["confusable"] = not result.get("npm_exists", False)
        return result
