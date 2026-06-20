"""
Core data models for IAM policy analysis.
"""

from typing import Any, Dict, List, Optional, Union
from enum import Enum
from dataclasses import dataclass, field


class Severity(str, Enum):
    """Severity levels for IAM violations."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PolicyType(str, Enum):
    """Supported policy types."""
    AWS_IAM = "aws_iam"
    OKTA = "okta"
    AZURE_AD = "azure_ad"
    GCP = "gcp"
    GENERIC = "generic"


@dataclass
class Finding:
    """A single policy violation finding."""
    
    check_id: str
    check_name: str
    severity: Severity
    message: str
    affected_resource: str
    remediation: str
    reference: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self):
        return hash((self.check_id, self.affected_resource, self.message))


@dataclass
class AnalysisResult:
    """Complete analysis result for a policy."""
    
    policy_type: PolicyType
    findings: List[Finding]
    analyzed_resources: int
    summary: Dict[str, int] = field(default_factory=dict)
    
    def __post_init__(self):
        """Calculate summary statistics."""
        self.summary = {
            "total": len(self.findings),
            "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
            "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
            "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
            "low": len([f for f in self.findings if f.severity == Severity.LOW]),
            "info": len([f for f in self.findings if f.severity == Severity.INFO]),
        }


@dataclass
class PolicyDocument:
    """Represents a parsed IAM policy document."""
    
    policy_type: PolicyType
    raw_policy: Union[Dict[str, Any], str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Normalized representation for universal analysis
    resources: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    principals: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    effect: Optional[str] = None
    name: Optional[str] = None
