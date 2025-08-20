# parsers.py
# Dependency file parsers for different formats

import json
import re

class DependencyParsers:
    @staticmethod
    def parse(file_type, body):
        if file_type == "package_json":
            try:
                data = json.loads(body)
                deps = []
                for key in ("dependencies", "devDependencies"):
                    if key in data:
                        deps.extend(list(data[key].keys()))
                return deps
            except Exception:
                return []
        elif file_type == "javascript":
            # Find require() and import statements
            require_re = re.compile(r'require\([\'\"]([\w\-\.\/]+)[\'\"]\)')
            import_re = re.compile(r'import\s+[\w\*\{\}]+\s+from\s+[\'\"]([\w\-\.\/]+)[\'\"]')
            deps = require_re.findall(body)
            deps += import_re.findall(body)
            return list(set(deps))
        elif file_type == "markdown":
            # Optionally parse markdown links referencing dependencies
            pattern = re.compile(r'\[(.*?)\]\((.*?)\)')
            return [m[1] for m in pattern.findall(body) if "npmjs.com" in m[1]]
        return []
