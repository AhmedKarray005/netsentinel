"""API configuration from environment variables (12-factor style: same code, different config)."""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    db_path: Path = Path("data/netsentinel.db")
    upload_dir: Path = Path("data/uploads")  # temporary files, deleted after analysis
    max_upload_mb: float = 50.0
    rules_file: Path | None = None  # optional TOML overriding detection thresholds
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)  # the dashboard dev server

    @property
    def max_upload_bytes(self) -> int:
        return int(self.max_upload_mb * 1024 * 1024)

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        rules = env.get("NETSENTINEL_RULES_FILE")
        origins = env.get("NETSENTINEL_CORS_ORIGINS")
        return cls(
            db_path=Path(env.get("NETSENTINEL_DB_PATH", cls.db_path)),
            upload_dir=Path(env.get("NETSENTINEL_UPLOAD_DIR", cls.upload_dir)),
            max_upload_mb=float(env.get("NETSENTINEL_MAX_UPLOAD_MB", cls.max_upload_mb)),
            rules_file=Path(rules) if rules else None,
            cors_origins=tuple(o.strip() for o in origins.split(",") if o.strip())
            if origins is not None
            else cls.cors_origins,
        )
