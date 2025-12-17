import os
from typing import List


class ConfigError(Exception):
    pass


def get_env(name: str, required: bool = True) -> str:
    """Retrieve environment variable or raise error if missing."""
    value = os.getenv(name)
    if required and not value:
        raise ConfigError(f"Missing required environment variable: {name}")
    return value


def get_targets() -> List[str]:
    """Parse TARGETS env variable into a list of IPs."""
    raw = get_env("TARGETS")
    targets = [t.strip() for t in raw.split(",") if t.strip()]
    if not targets:
        raise ConfigError("TARGETS is empty after parsing")
    return targets


class Config:
    """Global configuration object."""
    SHODAN_API_KEY: str = get_env("SHODAN_API_KEY")
    TARGETS: List[str] = get_targets()
