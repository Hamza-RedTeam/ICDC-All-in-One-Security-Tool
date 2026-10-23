import yaml
from pathlib import Path

class ConfigLoader:
    _instance = None

    def __new__(cls, path="config.yaml"):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load(path)
        return cls._instance

    def _load(self, path):
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        with open(p, "r") as f:
            self.config = yaml.safe_load(f)

    def get(self, *keys, default=None):
        node = self.config
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                return default
        return node

CONFIG = ConfigLoader()
