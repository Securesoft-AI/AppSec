"""Modelo de datos común: todos los motores normalizan sus resultados a `Finding`."""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        v = (value or "").strip().lower()
        aliases = {
            "error": "high",
            "warning": "medium",
            "moderate": "medium",
            "note": "low",
            "unknown": "medium",
            "": "medium",
        }
        v = aliases.get(v, v)
        try:
            return cls(v)
        except ValueError:
            return cls.MEDIUM


class Category(str, Enum):
    SAST = "sast"
    SECRETS = "secrets"
    SCA = "sca"
    IAC = "iac"
    AI = "ai"


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class Triage(BaseModel):
    """Resultado del análisis con IA de un hallazgo."""

    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    explanation: str
    exploit_scenario: str = ""
    fix: str = ""
    fixed_code: str = ""


class Finding(BaseModel):
    engine: str
    rule_id: str
    category: Category
    severity: Severity
    title: str
    message: str = ""
    file: str = ""
    line: int = 0
    end_line: int = 0
    snippet: str = ""
    references: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)  # p. ej. "OWASP-LLM01", "CWE-78"
    triage: Triage | None = None

    @property
    def fingerprint(self) -> str:
        """Identificador estable para deduplicar y cachear (no depende del número de línea)."""
        raw = f"{self.engine}|{self.rule_id}|{self.file}|{self.snippet.strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def effective_severity(self) -> Severity:
        return self.triage.severity if self.triage else self.severity

    @property
    def is_suppressed(self) -> bool:
        return bool(self.triage and self.triage.verdict == Verdict.FALSE_POSITIVE)


class AIComponent(BaseModel):
    """Elemento del inventario de IA detectado en el código."""

    kind: str  # "llm_sdk", "framework", "model", "agent_tool", "mcp_server", "vector_store"
    name: str
    file: str
    line: int
    detail: str = ""


class EngineRun(BaseModel):
    engine: str
    status: str  # "ok", "skipped", "error"
    detail: str = ""
    findings: int = 0


class ScanResult(BaseModel):
    target: str
    findings: list[Finding] = Field(default_factory=list)
    ai_inventory: list[AIComponent] = Field(default_factory=list)
    engines: list[EngineRun] = Field(default_factory=list)
    suppressed_inline: int = 0
    ai_summary: str = ""
    llm_usage: dict[str, int] = Field(default_factory=dict)
