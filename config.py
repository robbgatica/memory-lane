"""Configuration for Memory Forensics MCP Server"""
import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "artifacts.db"

# Volatility 3 path
VOLATILITY_PATH = Path(os.path.expanduser("~/tools/volatility3"))

# Memory dumps location
DUMPS_DIR = Path(os.path.expanduser("~/tools/memdumps"))

# Export directories
EXPORT_DIR = DATA_DIR / "exports"
EXTRACTED_FILES_DIR = DATA_DIR / "extracted"
EXTRACTION_DIR = DATA_DIR / "extractions"  # For extracted memory dumps
TEMPLATES_DIR = PROJECT_ROOT / "templates"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
EXPORT_DIR.mkdir(exist_ok=True)
EXTRACTED_FILES_DIR.mkdir(exist_ok=True)
EXTRACTION_DIR.mkdir(exist_ok=True)

# Cleanup settings
EXTRACTION_RETENTION_HOURS = 24  # Keep extractions for 24 hours
AUTO_CLEANUP_ON_STARTUP = True  # Clean old extractions at startup

# Volatility 3 configuration
VOLATILITY_PLUGINS_PATH = VOLATILITY_PATH / "volatility3" / "framework" / "plugins"
VOLATILITY_SYMBOLS_PATH = VOLATILITY_PATH / "volatility3" / "symbols"

# Hash algorithms to calculate
HASH_ALGORITHMS = ['md5', 'sha1', 'sha256']

# Export settings
DEFAULT_EXPORT_FORMAT = "json"
INCLUDE_PROVENANCE_BY_DEFAULT = True

# LLM Profile Configuration
class LLMProfile:
    """Profiles for different LLM capabilities

    Different LLMs have different capabilities and context limits.
    These profiles optimize tool descriptions and output formats.
    """
    CLAUDE = "claude"           # Claude (Opus/Sonnet) - Full features, detailed descriptions
    LLAMA_70B = "llama70b"      # Llama 3.1 70B - Full features, moderate descriptions
    LLAMA_13B = "llama13b"      # Llama 13B or smaller - Simplified descriptions
    GPT4 = "gpt4"               # GPT-4 - Full features, detailed descriptions
    MINIMAL = "minimal"         # Any small model - Bare minimum descriptions

# Current LLM profile (can be overridden via MCP_LLM_PROFILE env variable)
LLM_PROFILE = os.getenv("MCP_LLM_PROFILE", LLMProfile.CLAUDE)

# Output format preferences per profile
LLM_OUTPUT_PREFERENCES = {
    LLMProfile.CLAUDE: {
        "format": "markdown",
        "verbosity": "detailed",
        "include_examples": True,
        "max_description_length": 500,
    },
    LLMProfile.LLAMA_70B: {
        "format": "markdown",
        "verbosity": "moderate",
        "include_examples": True,
        "max_description_length": 300,
    },
    LLMProfile.LLAMA_13B: {
        "format": "json",
        "verbosity": "concise",
        "include_examples": False,
        "max_description_length": 150,
    },
    LLMProfile.GPT4: {
        "format": "markdown",
        "verbosity": "detailed",
        "include_examples": True,
        "max_description_length": 500,
    },
    LLMProfile.MINIMAL: {
        "format": "json",
        "verbosity": "minimal",
        "include_examples": False,
        "max_description_length": 100,
    },
}

# Get current profile settings
CURRENT_PROFILE_SETTINGS = LLM_OUTPUT_PREFERENCES.get(
    LLM_PROFILE,
    LLM_OUTPUT_PREFERENCES[LLMProfile.CLAUDE]
)
