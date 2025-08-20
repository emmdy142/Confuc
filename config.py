# config.py
# Configuration manager

import json
import os

class ConfigManager:
    def __init__(self, config_path):
        self.path = config_path
        self.config = self._load_config()

    def _load_config(self):
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                return json.load(f)
        # Default config
        return {
            "real_time_monitoring": True,
            "file_types": {
                ".js": "javascript",
                ".json": "package_json",
                ".md": "markdown"
            },
            "enable_npm": True
        }

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.config, f, indent=2)
