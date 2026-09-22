"""
Configuration module for AutoSchema & API Auditor Agent.
Supports environment variables, .env file loading, and sensible defaults for Nebius Token Factory and Tavily.
"""

import os
from pathlib import Path

def load_dotenv_fallback(dotenv_path: str = ".env"):
    """Lightweight .env loader without external dependencies."""
    p = Path(dotenv_path)
    if not p.exists():
        return
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'\"")
            if key not in os.environ:
                os.environ[key] = val

# Try loading from .env
load_dotenv_fallback()

class Config:
    # Nebius Token Factory Configuration
    NEBIUS_API_KEY = os.getenv("NEBIUS_API_KEY", "")
    NEBIUS_BASE_URL = os.getenv("NEBIUS_BASE_URL", "https://api.studio.nebius.ai/v1")
    MODEL_NAME = os.getenv("MODEL_NAME", "nvidia/nemotron-3-super-120b-instruct")

    # Tavily Search API Configuration
    TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
    TAVILY_BASE_URL = os.getenv("TAVILY_BASE_URL", "https://api.tavily.com/search")

    # Agent Execution Hyperparameters
    TEMPERATURE = float(os.getenv("AGENT_TEMPERATURE", "0.1"))
    MAX_TOOL_ITERATIONS = int(os.getenv("MAX_TOOL_ITERATIONS", "6"))
    DEFAULT_DATABASE_DIALECT = os.getenv("DEFAULT_DATABASE_DIALECT", "PostgreSQL 16")

    # Output directory for audit reports
    REPORTS_DIR = os.getenv("REPORTS_DIR", "reports")

    @classmethod
    def is_nebius_configured(cls) -> bool:
        return bool(cls.NEBIUS_API_KEY and cls.NEBIUS_API_KEY != "your-nebius-api-key-here")

    @classmethod
    def is_tavily_configured(cls) -> bool:
        return bool(cls.TAVILY_API_KEY and cls.TAVILY_API_KEY != "your-tavily-api-key-here")
