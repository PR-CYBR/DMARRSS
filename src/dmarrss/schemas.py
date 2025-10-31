"""
Core data schemas for DMARRSS using Pydantic for validation and serialization.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class LogSource(str, Enum):
    """Supported log source types"""

    SNORT = "SNORT"
    SURICATA = "SURICATA"
    ZEEK = "ZEEK"


class Severity(str, Enum):
    """Threat severity levels"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Event(BaseModel):
    """
    Canonical event model representing a parsed security event.

    All parsers must convert their native formats to this schema.
    """

    # Metadata
    source: LogSource
    ts: datetime
    event_id: str | None = None

    # Network information
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    proto: str | None = None

    # Threat information
    category: str | None = None
    signature: str | None = None
    severity_hint: str | None = None

    # Raw data and metadata
    raw: dict[str, Any] | str = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    # Computed fields (set during processing)
    threat_score: float | None = None
    severity: Severity | None = None

    @field_validator("ts", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        """Parse various timestamp formats"""
        if isinstance(v, datetime):
            return v
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v)
        if isinstance(v, str):
            # Try common formats
            for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
                try:
                    return datetime.strptime(v, fmt)
                except ValueError:
                    continue
            # Fallback to ISO format
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v

    class Config:
        use_enum_values = True


class Decision(BaseModel):
    """
    Decision object produced by the decision engine.

    Contains severity classification, confidence, and rationale.
    """

    decision_id: str
    event_id: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Rationale and scoring components
    threat_score: float = Field(ge=0.0, le=1.0)
    score_components: dict[str, float] = Field(default_factory=dict)
    neural_prediction: str | None = None
    neural_confidence: float | None = None

    # Decision reasoning
    why: str = ""
    weights: dict[str, float] = Field(default_factory=dict)

    # Response policy
    recommended_actions: list[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True


class ActionResult(BaseModel):
    """
    Result of executing an action plugin.
    """

    action_id: str
    decision_id: str
    action_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Execution details
    success: bool
    dry_run: bool
    executed: bool  # False in dry-run, True when actually executed

    # Details
    message: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None

    class Config:
        use_enum_values = True


class ThreatScoreComponents(BaseModel):
    """Individual components of the threat score"""

    pattern_match: float = Field(ge=0.0, le=1.0)
    context_relevance: float = Field(ge=0.0, le=1.0)
    historical_severity: float = Field(ge=0.0, le=1.0)
    source_reputation: float = Field(ge=0.0, le=1.0)
    anomaly_score: float = Field(ge=0.0, le=1.0)


class ModelMetadata(BaseModel):
    """Metadata for trained neural models"""

    model_version: str
    trained_at: datetime
    training_samples: int
    validation_accuracy: float
    features: list[str]
    architecture: dict[str, Any] = Field(default_factory=dict)
    hyperparameters: dict[str, Any] = Field(default_factory=dict)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
