"""
Check framework for policy analysis.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from iam_policy_analyzer.models import Finding, PolicyDocument, Severity


class PolicyCheck(ABC):
    """Base class for all IAM policy checks."""
    
    check_id: str
    check_name: str
    description: str
    severity: Severity
    
    def __init__(self):
        """Initialize the check."""
        if not hasattr(self, 'check_id'):
            raise NotImplementedError(f"{self.__class__.__name__} must define check_id")
        if not hasattr(self, 'check_name'):
            raise NotImplementedError(f"{self.__class__.__name__} must define check_name")
        if not hasattr(self, 'severity'):
            raise NotImplementedError(f"{self.__class__.__name__} must define severity")
    
    @abstractmethod
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        """
        Analyze a policy and return findings.
        
        Args:
            policy: PolicyDocument to analyze
            
        Returns:
            List of Finding objects for violations found
        """
        pass
    
    def _create_finding(
        self,
        message: str,
        affected_resource: str,
        remediation: str,
        reference: str = None,
        details: Dict[str, Any] = None,
    ) -> Finding:
        """Helper to create a Finding."""
        return Finding(
            check_id=self.check_id,
            check_name=self.check_name,
            severity=self.severity,
            message=message,
            affected_resource=affected_resource,
            remediation=remediation,
            reference=reference,
            details=details or {},
        )


class CheckRegistry:
    """Registry for managing all available checks."""
    
    def __init__(self):
        self._checks: Dict[str, PolicyCheck] = {}
    
    def register(self, check: PolicyCheck) -> None:
        """Register a check."""
        self._checks[check.check_id] = check
    
    def get_all(self) -> List[PolicyCheck]:
        """Get all registered checks."""
        return list(self._checks.values())
    
    def get_by_id(self, check_id: str) -> PolicyCheck:
        """Get a check by ID."""
        return self._checks.get(check_id)
    
    def get_by_severity(self, severity: Severity) -> List[PolicyCheck]:
        """Get all checks of a specific severity."""
        return [c for c in self._checks.values() if c.severity == severity]
