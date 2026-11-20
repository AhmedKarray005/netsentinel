"""Detection thresholds. Defaults live here; a TOML file can override any of them."""

import tomllib
from dataclasses import dataclass, fields, replace
from pathlib import Path


class ConfigError(Exception):
    """The rules file is unreadable or contains an unknown key / invalid value."""


@dataclass(frozen=True)
class PortScanConfig:
    enabled: bool = True
    window_seconds: float = 60.0  # sliding time window
    min_distinct_ports: int = 20  # distinct destination ports, one source -> one destination
    high_severity_ports: int = 100  # at or above this: severity "high"


@dataclass(frozen=True)
class TrafficSpikeConfig:
    enabled: bool = True
    bucket_seconds: float = 1.0  # rate is measured per bucket
    min_packets: int = 1000  # absolute floor: packets from one source in one bucket
    baseline_multiplier: float = 10.0  # ...and at least this many times the source's usual rate
    high_severity_multiplier: float = 5.0  # peak >= min_packets x this: severity "high"
    min_baseline_buckets: int = 10  # shorter capture: no reliable baseline, floor only


@dataclass(frozen=True)
class FailedConnectionsConfig:
    enabled: bool = True
    window_seconds: float = 60.0
    min_failed: int = 10  # failed TCP attempts, one source -> same destination IP and port
    medium_severity_failed: int = 50  # at or above this: severity "medium" (else "low")


@dataclass(frozen=True)
class DetectionConfig:
    port_scan: PortScanConfig = PortScanConfig()
    traffic_spike: TrafficSpikeConfig = TrafficSpikeConfig()
    failed_connections: FailedConnectionsConfig = FailedConnectionsConfig()


def load_config(path: str | Path | None = None) -> DetectionConfig:
    """Defaults, overridden by the sections present in the TOML file (if any)."""
    config = DetectionConfig()
    if path is None:
        return config
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot read rules file {path}: {exc}") from exc

    sections = {f.name: getattr(config, f.name) for f in fields(DetectionConfig)}
    unknown = set(data) - set(sections)
    if unknown:
        raise ConfigError(f"Unknown section(s) in {path}: {sorted(unknown)}")
    updated = {name: _override(name, sections[name], data.get(name, {})) for name in sections}
    return DetectionConfig(**updated)


def _override(section: str, current, values: dict):
    allowed = {f.name: f.type for f in fields(current)}
    for key, value in values.items():
        if key not in allowed:
            raise ConfigError(f"Unknown key [{section}].{key}")
        expected = allowed[key]
        if expected is bool and not isinstance(value, bool):
            raise ConfigError(f"[{section}].{key} must be true or false")
        if expected in (int, float):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ConfigError(f"[{section}].{key} must be a number")
            if value <= 0:
                raise ConfigError(f"[{section}].{key} must be greater than 0")
            if expected is int and not float(value).is_integer():
                raise ConfigError(f"[{section}].{key} must be a whole number")
    return replace(current, **values)
