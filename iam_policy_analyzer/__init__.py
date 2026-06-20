"""
IAM Policy Analyzer - Automated security analysis for IAM policies.
"""

__version__ = "0.1.0"
__author__ = "Amit Gupta"
__email__ = "apphelp.csw@gmail.com"
__license__ = "MIT"

from iam_policy_analyzer.models import Finding, AnalysisResult, PolicyDocument, Severity
from iam_policy_analyzer.analyzer import IAMAnalyzer, PolicyParser

__all__ = [
    "Finding",
    "AnalysisResult", 
    "PolicyDocument",
    "Severity",
    "IAMAnalyzer",
    "PolicyParser",
]
