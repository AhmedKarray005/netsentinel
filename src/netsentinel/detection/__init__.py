"""Rule-based detection: turns flows and packet rates into alerts with evidence."""

from netsentinel.detection.config import ConfigError, DetectionConfig, load_config
from netsentinel.detection.engine import DetectionEngine
from netsentinel.detection.models import Alert, Rule

__all__ = ["Alert", "ConfigError", "DetectionConfig", "DetectionEngine", "Rule", "load_config"]
