"""
Policy parser and analyzer engine.
"""

import json
import yaml
from typing import Dict, Any, List, Union
from pathlib import Path

from iam_policy_analyzer.models import PolicyDocument, PolicyType, AnalysisResult, Finding
from iam_policy_analyzer.checks import CheckRegistry, PolicyCheck
from iam_policy_analyzer.security_checks import (
    WildcardPrincipalCheck,
    WildcardActionCheck,
    WildcardResourceCheck,
    AdminAccessCheck,
    MissingMFACheck,
    CredentialExposureCheck,
    PassAssumeRoleCheck,
    PermissionBoundaryCheck,
    UnencryptedDataAccessCheck,
    DeprecatedApiCheck,
    ResourceTagCheck,
    DenyPolicyMissingCheck,
)


class PolicyParser:
    """Parses IAM policies from various formats."""
    
    @staticmethod
    def parse_file(file_path: str) -> PolicyDocument:
        """Parse a policy file and return PolicyDocument."""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {file_path}")
        
        content = path.read_text()
        
        # Try JSON first
        try:
            policy = json.loads(content)
            return PolicyParser.parse_policy(policy, PolicyType.GENERIC)
        except json.JSONDecodeError:
            pass
        
        # Try YAML
        try:
            policy = yaml.safe_load(content)
            return PolicyParser.parse_policy(policy, PolicyType.GENERIC)
        except yaml.YAMLError:
            raise ValueError(f"Unable to parse policy file: {file_path}. "
                           "Supported formats: JSON, YAML")
    
    @staticmethod
    def parse_policy(policy: Union[Dict[str, Any], str], 
                     policy_type: PolicyType = PolicyType.GENERIC) -> PolicyDocument:
        """Parse a policy dict/object and return PolicyDocument."""
        
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                policy = yaml.safe_load(policy)
        
        # Create normalized document
        doc = PolicyDocument(
            policy_type=policy_type,
            raw_policy=policy,
        )
        
        # Parse based on type
        if policy_type == PolicyType.AWS_IAM:
            PolicyParser._parse_aws_iam(policy, doc)
        elif policy_type == PolicyType.OKTA:
            PolicyParser._parse_okta(policy, doc)
        elif policy_type == PolicyType.AZURE_AD:
            PolicyParser._parse_azure(policy, doc)
        else:
            PolicyParser._parse_generic(policy, doc)
        
        # Set name/metadata
        if isinstance(policy, dict):
            doc.name = policy.get("Name") or policy.get("PolicyName") or policy.get("name")
            doc.metadata = {k: v for k, v in policy.items() 
                          if k not in ["Statement", "Statements"]}
        
        return doc
    
    @staticmethod
    def _parse_aws_iam(policy: Dict[str, Any], doc: PolicyDocument) -> None:
        """Parse AWS IAM policy format."""
        statements = policy.get("Statement", [])
        
        if not isinstance(statements, list):
            statements = [statements]
        
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            
            # Parse Principal
            principal = stmt.get("Principal")
            if principal:
                if isinstance(principal, str):
                    doc.principals.append(principal)
                elif isinstance(principal, dict):
                    for key, val in principal.items():
                        if isinstance(val, str):
                            doc.principals.append(val)
                        elif isinstance(val, list):
                            doc.principals.extend(val)
            
            # Parse Action
            action = stmt.get("Action")
            if action:
                if isinstance(action, str):
                    doc.actions.append(action)
                elif isinstance(action, list):
                    doc.actions.extend(action)
            
            # Parse Resource
            resource = stmt.get("Resource")
            if resource:
                if isinstance(resource, str):
                    doc.resources.append(resource)
                elif isinstance(resource, list):
                    doc.resources.extend(resource)
            
            # Parse Condition
            if "Condition" in stmt:
                doc.conditions.update(stmt.get("Condition", {}))
            
            # Parse Effect
            if "Effect" in stmt and not doc.effect:
                doc.effect = stmt.get("Effect")
    
    @staticmethod
    def _parse_okta(policy: Dict[str, Any], doc: PolicyDocument) -> None:
        """Parse Okta policy format."""
        # Okta uses rules/groups instead of statements
        if "rules" in policy:
            for rule in policy.get("rules", []):
                if isinstance(rule, dict):
                    # Extract actions/scopes
                    if "actions" in rule:
                        actions = rule.get("actions")
                        if isinstance(actions, list):
                            doc.actions.extend(actions)
                        else:
                            doc.actions.append(actions)
        
        # Parse groups if present
        if "groups" in policy:
            groups = policy.get("groups")
            if isinstance(groups, list):
                doc.principals.extend(groups)
            else:
                doc.principals.append(groups)
    
    @staticmethod
    def _parse_azure(policy: Dict[str, Any], doc: PolicyDocument) -> None:
        """Parse Azure AD policy format."""
        # Azure uses AssignableScopes and Permissions
        if "AssignableScopes" in policy:
            scopes = policy.get("AssignableScopes", [])
            if isinstance(scopes, list):
                doc.resources.extend(scopes)
        
        if "Permissions" in policy:
            perms = policy.get("Permissions", [])
            if isinstance(perms, list):
                for perm in perms:
                    if isinstance(perm, dict):
                        actions = perm.get("Actions", [])
                        if isinstance(actions, list):
                            doc.actions.extend(actions)
    
    @staticmethod
    def _parse_generic(policy: Dict[str, Any], doc: PolicyDocument) -> None:
        """Parse generic policy format (flexible structure)."""
        # If it looks like AWS IAM with Statement, use AWS parser
        if "Statement" in policy:
            PolicyParser._parse_aws_iam(policy, doc)
            return
        
        # Try common field names
        for action_key in ["Action", "Actions", "actions", "permissions"]:
            if action_key in policy:
                actions = policy[action_key]
                if isinstance(actions, list):
                    doc.actions.extend(actions)
                else:
                    doc.actions.append(actions)
                break
        
        for resource_key in ["Resource", "Resources", "resources"]:
            if resource_key in policy:
                resources = policy[resource_key]
                if isinstance(resources, list):
                    doc.resources.extend(resources)
                else:
                    doc.resources.append(resources)
                break
        
        for principal_key in ["Principal", "Principals", "principals"]:
            if principal_key in policy:
                principals = policy[principal_key]
                if isinstance(principals, list):
                    doc.principals.extend(principals)
                else:
                    doc.principals.append(principals)
                break


class IAMAnalyzer:
    """Main analyzer engine."""
    
    def __init__(self):
        """Initialize the analyzer with all checks."""
        self.registry = CheckRegistry()
        self._register_checks()
    
    def _register_checks(self) -> None:
        """Register all security checks."""
        checks = [
            WildcardPrincipalCheck(),
            WildcardActionCheck(),
            WildcardResourceCheck(),
            AdminAccessCheck(),
            MissingMFACheck(),
            CredentialExposureCheck(),
            PassAssumeRoleCheck(),
            PermissionBoundaryCheck(),
            UnencryptedDataAccessCheck(),
            DeprecatedApiCheck(),
            ResourceTagCheck(),
            DenyPolicyMissingCheck(),
        ]
        
        for check in checks:
            self.registry.register(check)
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a policy file."""
        policy_doc = PolicyParser.parse_file(file_path)
        return self.analyze_policy(policy_doc)
    
    def analyze_policy(self, policy: PolicyDocument) -> AnalysisResult:
        """Analyze a parsed policy document."""
        findings: List[Finding] = []
        
        # Run all checks
        for check in self.registry.get_all():
            try:
                check_findings = check.analyze(policy)
                findings.extend(check_findings)
            except Exception as e:
                # Don't fail on individual check errors
                print(f"Warning: Check {check.check_id} failed: {e}")
        
        # Deduplicate findings
        findings = list(set(findings))
        
        # Count analyzed resources
        resource_count = len(policy.resources) + len(policy.actions) + len(policy.principals)
        
        result = AnalysisResult(
            policy_type=policy.policy_type,
            findings=findings,
            analyzed_resources=resource_count,
        )
        
        return result
    
    def analyze_multiple(self, file_paths: List[str]) -> Dict[str, AnalysisResult]:
        """Analyze multiple policy files."""
        results = {}
        
        for file_path in file_paths:
            try:
                results[file_path] = self.analyze_file(file_path)
            except Exception as e:
                print(f"Error analyzing {file_path}: {e}")
        
        return results
