import os
import json
import logging
from pathlib import Path
from pydantic import BaseModel, Field

logger = logging.getLogger("reposhield")

class RepoShieldConfig(BaseModel):
    version: str = "1.0"
    ignored_severities: list[str] = Field(default_factory=list)
    ignored_categories: list[str] = Field(default_factory=list)
    strict_mode: bool = False
    risk_threshold: float = 5.0         # Risk score >= this triggers FAIL verdict
    block_on_secrets: bool = True       # Always FAIL if secrets are found
    block_on_critical: bool = True      # Always FAIL if CRITICAL severity found

def get_config_path() -> Path:
    home = Path(os.path.expanduser("~"))
    reposhield_dir = home / ".reposhield"
    reposhield_dir.mkdir(exist_ok=True)
    return reposhield_dir / "config.json"

def load_config() -> dict:
    config_path = get_config_path()
    if not config_path.exists():
        default_cfg = RepoShieldConfig()
        save_config(default_cfg.model_dump())
        return default_cfg.model_dump()
        
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Validate with Pydantic
            valid_config = RepoShieldConfig(**data)
            return valid_config.model_dump()
    except Exception as e:
        # Log a warning instead of silently swallowing the error
        logger.warning(f"Config file corrupted or invalid, using defaults: {e}")
        default_cfg = RepoShieldConfig()
        return default_cfg.model_dump()

def save_config(config: dict):
    # Ensure it's valid before saving
    try:
        valid_config = RepoShieldConfig(**config)
    except Exception as e:
        logger.warning(f"Invalid config data provided, saving defaults instead: {e}")
        valid_config = RepoShieldConfig()
        
    config_path = get_config_path()
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(valid_config.model_dump(), f, indent=4)