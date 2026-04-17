from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class RunContext:
    fixture_dir: Path
    manifest: Dict[str, Any]
    output_dir: Path
    profile_set_name: str
    mode: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Hypothesis:
    attack_family: str
    confidence: float
    rationale: str
    evidence_ids: List[str] = field(default_factory=list)
    required_skill: str = "analysis"


@dataclass
class CandidatePoC:
    attack_family: str
    title: str
    steps: List[Dict[str, Any]]
    oracle: str
    confidence: float
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    status: str
    attack_family: Optional[str]
    severity: Optional[str]
    confidence: float
    evidence: List[str]
    reasoning: str
    poc: Optional[CandidatePoC] = None


@dataclass
class ModelProfile:
    name: str
    label: str
    reasoning: float
    analysis: float
    coding: float
    reporting: float
    recon: float
    validation: float
    cost_per_step: float
    simulated_tokens_per_step: int
