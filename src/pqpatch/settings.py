"""Runtime configuration.

This is the only module that reads environment variables. Everything else
receives a Settings value explicitly, which keeps the offline guarantee
enforceable and the configuration testable in isolation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    offline: bool
    cache_dir: Path
    runs_dir: Path
    repo_root: Path
    backend_a_api_key: str | None
    backend_b_api_key: str | None
    backend_c_base_url: str
    # OpenAI-compatible endpoint for backend A. Defaults to OpenAI; point it at
    # any compatible host (e.g. https://api.deepseek.com) via the env var.
    backend_a_base_url: str = "https://api.openai.com/v1"

    @classmethod
    def load(cls) -> Settings:
        repo_root = Path(__file__).resolve().parents[2]
        return cls(
            offline=os.environ.get("PQPATCH_OFFLINE", "0") == "1",
            cache_dir=Path(
                os.environ.get(
                    "PQPATCH_CACHE_DIR", str(repo_root / "src" / "pqpatch" / "proposer" / "cache")
                )
            ),
            runs_dir=Path(os.environ.get("PQPATCH_RUNS_DIR", str(repo_root / "runs"))),
            repo_root=repo_root,
            # None means "not configured"; the backend adapters refuse to
            # run a live call without a key rather than defaulting one.
            backend_a_api_key=os.environ.get("PQPATCH_BACKEND_A_API_KEY"),
            backend_b_api_key=os.environ.get("PQPATCH_BACKEND_B_API_KEY"),
            backend_c_base_url=os.environ.get(
                "PQPATCH_BACKEND_C_BASE_URL", "http://localhost:8000/v1"
            ),
            backend_a_base_url=os.environ.get(
                "PQPATCH_BACKEND_A_BASE_URL", "https://api.openai.com/v1"
            ),
        )


def get_settings() -> Settings:
    """Kept as a function rather than a module-level singleton so tests can
    construct fresh Settings freely."""
    return Settings.load()
