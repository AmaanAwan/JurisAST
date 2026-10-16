"""
Configuration settings for the JurisAST Benchmark Suite and Gemini API.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class BenchmarkConfig:
    """Benchmark execution and API settings."""
    api_key: Optional[str] = None
    model: str = "google:gemini-2.5-flash"
    use_pilot: bool = True
    pilot_count: int = 60
    full_count: int = 500
    timeout_seconds: float = 30.0
    rate_limit_rpm: int = 30  # Max requests per minute for Gemini free/tier-1 quota
    enable_gemini_baseline: bool = True
    enable_heuristic_baseline: bool = True
    seed: int = 42

    def resolve_api_key(self) -> Optional[str]:
        """
        Resolve API key from explicit config, GOOGLE_API_KEY, or GEMINI_API_KEY.
        Sets os.environ["GOOGLE_API_KEY"] for downstream SDK compatibility.
        """
        raw_key = (
            self.api_key
            or os.environ.get("GOOGLE_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
        )
        if raw_key and str(raw_key).strip() and str(raw_key).strip().lower() != "none":
            key = str(raw_key).strip()
            self.api_key = key
            os.environ["GOOGLE_API_KEY"] = key
            os.environ["GEMINI_API_KEY"] = key
            return key
        self.api_key = None
        return None

    @property
    def has_api_key(self) -> bool:
        return bool(self.resolve_api_key())
