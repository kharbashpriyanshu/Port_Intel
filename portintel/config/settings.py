import os
from pathlib import Path
from typing import Optional


class Settings:
    """
    Centralized configuration settings for PortIntel.
    """
    # General Scan Settings
    DEFAULT_TIMEOUT: float = 0.5
    DEFAULT_THREADS: int = 100
    MAX_THREADS: int = 1000

    # NVD API Integration
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_TIMEOUT: int = 5
    NVD_API_KEY: Optional[str] = os.environ.get("NVD_API_KEY", None)
    USER_AGENT: str = "PortIntel-Scanner/2.0.0"

    # Output/Reporting
    DEFAULT_OUTPUT_DIR: Path = Path("reports")

    @classmethod
    def setup_directories(cls):
        """Creates necessary directories if they don't exist."""
        cls.DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Global settings instance
config = Settings()
