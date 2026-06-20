"""
Concrete security checks for IAM policy analysis.
"""

from typing import List, Any
import re
from iam_policy_analyzer.checks import PolicyCheck
from iam_policy_analyzer.models import Finding, PolicyDocument, Severity


class WildcardPrincipalCheck(PolicyCheck):
    """Detect overly permissive wildcard (*) principals."""
    
    check_id = "IAM-001"
    check_name = "Wildcard Principal Detected"
    description = "Policy grants access to all principals (*), which violates principle of least privilege"
    severity = Severity.CRITICAL
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # Check principals
        if "*" in policy.principals or ["*"] == policy.principals:
            findings.append(self._create_finding(
                message="Policy allows access from any principal (wildcard)",
                affected_resource=policy.name or "Unknown",
                remediation="Replace wildcard principal with specific AWS account IDs, IAM roles, or service principals. "
                          "Use principal whitelisting instead of wildcards.",
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
            ))
        
        return findings


class WildcardActionCheck(PolicyCheck):
    """Detect overly permissive wildcard (*) actions."""
    
    check_id = "IAM-002"
    check_name = "Wildcard Action Detected"
    description = "Policy grants all actions (*), violating least privilege principle"
    severity = Severity.CRITICAL
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        if "*" in policy.actions or ["*"] == policy.actions:
            findings.append(self._create_finding(
                message="Policy allows all actions (*), granting excessive permissions",
                affected_resource=policy.name or "Unknown",
                remediation="Replace wildcard actions with specific, necessary permissions. "
                          "Example: Use 's3:GetObject' instead of 's3:*'",
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html"
            ))
        
        return findings


class WildcardResourceCheck(PolicyCheck):
    """Detect overly permissive wildcard (*) resources."""
    
    check_id = "IAM-003"
    check_name = "Wildcard Resource Detected"
    description = "Policy grants access to all resources (*)"
    severity = Severity.HIGH
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        if "*" in policy.resources or ["*"] == policy.resources:
            findings.append(self._create_finding(
                message="Policy allows access to all resources (*)",
                affected_resource=policy.name or "Unknown",
                remediation="Restrict resources to specific ARNs. "
                          "Example: 'arn:aws:s3:::my-bucket/*' instead of '*'",
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html"
            ))
        
        return findings


class AdminAccessCheck(PolicyCheck):
    """Detect policies granting administrative access."""
    
    check_id = "IAM-004"
    check_name = "Administrative Access Detected"
    description = "Policy grants administrative or near-administrative permissions"
    severity = Severity.CRITICAL
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        admin_patterns = [
            "*:*",
            "iam:*",
            "organizations:*",
            "securityhub:*",
            "*:CreateAccessKey",
            "*:AttachUserPolicy",
            "*:PutUserPolicy",
            "sts:AssumeRole",
        ]
        
        for action in policy.actions:
            for pattern in admin_patterns:
                if self._matches_pattern(action, pattern):
                    findings.append(self._create_finding(
                        message=f"Policy includes administrative action: {action}",
                        affected_resource=policy.name or "Unknown",
                        remediation="Restrict administrative actions to principal roles (e.g., IAM admins only). "
                                  "Use IAM permission boundaries to limit privilege escalation.",
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
                        details={"action": action}
                    ))
                    break
        
        return findings
    
    @staticmethod
    def _matches_pattern(action: str, pattern: str) -> bool:
        """Check if action matches a permission pattern."""
        regex = pattern.replace("*", ".*").replace(":", r"\:")
        return bool(re.match(f"^{regex}$", action, re.IGNORECASE))


class MissingMFACheck(PolicyCheck):
    """Detect policies allowing sensitive actions without MFA."""
    
    check_id = "IAM-005"
    check_name = "Sensitive Action Without MFA Requirement"
    description = "Policy allows sensitive actions without requiring MFA"
    severity = Severity.HIGH
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        sensitive_actions = [
            "iam:DeleteUser",
            "iam:DeleteAccessKey",
            "iam:DeletePolicy",
            "iam:PutUserPolicy",
            "organizations:LeaveOrganization",
            "kms:DisableKey",
            "kms:ScheduleKeyDeletion",
        ]
        
        # Check if any sensitive action is present without MFA condition
        has_sensitive_action = any(
            any(self._matches_pattern(a, sa) for sa in sensitive_actions)
            for a in policy.actions
        )
        
        has_mfa_condition = self._check_mfa_condition(policy.conditions)
        
        if has_sensitive_action and not has_mfa_condition:
            findings.append(self._create_finding(
                message="Policy allows sensitive actions without requiring MFA",
                affected_resource=policy.name or "Unknown",
                remediation="Add MFA requirement to the policy condition: "
                          '"aws:MultiFactorAuthPresent": "true"',
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-multifactorauthpresent"
            ))
        
        return findings
    
    @staticmethod
    def _matches_pattern(action: str, pattern: str) -> bool:
        """Check if action matches a permission pattern."""
        regex = pattern.replace("*", ".*").replace(":", r"\:")
        return bool(re.match(f"^{regex}$", action, re.IGNORECASE))
    
    @staticmethod
    def _check_mfa_condition(conditions: dict) -> bool:
        """Check if MFA condition is present."""
        if not conditions:
            return False
        for key, value in conditions.items():
            if "mfa" in key.lower() or "multifactor" in key.lower():
                return True
        return False


class CredentialExposureCheck(PolicyCheck):
    """Detect hardcoded credentials or secret exposure."""
    
    check_id = "IAM-006"
    check_name = "Potential Credential Exposure"
    description = "Policy or configuration may expose credentials"
    severity = Severity.CRITICAL
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # Check raw policy for common credential patterns
        policy_str = str(policy.raw_policy).lower()
        
        credential_patterns = [
            r"awsaccesskeyid",
            r"aws_secret_access_key",
            r"password.*[=:].*\S",
            r"secret.*[=:].*\S",
            r"api[_-]?key.*[=:].*\S",
            r"token.*[=:].*\S",
            r"bearer\s+\S+",
        ]
        
        for pattern in credential_patterns:
            if re.search(pattern, policy_str):
                findings.append(self._create_finding(
                    message="Policy or configuration may contain hardcoded credentials",
                    affected_resource=policy.name or "Unknown",
                    remediation="Remove all hardcoded credentials. Use AWS Secrets Manager or Parameter Store. "
                              "Never commit credentials to version control.",
                    reference="https://docs.aws.amazon.com/secretsmanager/latest/userguide/"
                ))
                break
        
        return findings


class PassAssumeRoleCheck(PolicyCheck):
    """Detect overly permissive PassRole permissions."""
    
    check_id = "IAM-007"
    check_name = "Overly Permissive PassRole Detected"
    description = "Policy allows passing any role without restrictions"
    severity = Severity.HIGH
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # Check for iam:PassRole with wildcard resources
        has_pass_role = any(
            "passrole" in action.lower() 
            for action in policy.actions
        )
        
        has_wildcard_resource = "*" in policy.resources or ["*"] == policy.resources
        
        if has_pass_role and has_wildcard_resource:
            findings.append(self._create_finding(
                message="Policy allows passing any role (iam:PassRole with * resources)",
                affected_resource=policy.name or "Unknown",
                remediation="Restrict PassRole to specific roles. Example: "
                          '"Resource": "arn:aws:iam::ACCOUNT:role/MySpecificRole"',
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html"
            ))
        
        return findings


class PermissionBoundaryCheck(PolicyCheck):
    """Detect missing permission boundaries for user/role creation."""
    
    check_id = "IAM-008"
    check_name = "No Permission Boundary Enforcement"
    description = "Policy allows creating users/roles without permission boundaries"
    severity = Severity.MEDIUM
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # Check for user/role creation permissions
        creation_actions = [
            "iam:CreateUser",
            "iam:CreateRole",
            "iam:PutUserPolicy",
            "iam:AttachUserPolicy",
        ]
        
        has_creation = any(
            any(self._matches_pattern(a, ca) for ca in creation_actions)
            for a in policy.actions
        )
        
        # Check for PermissionsBoundary requirement
        has_boundary = any(
            "permissionsboundary" in str(cond).lower()
            for cond in policy.conditions.values()
        )
        
        if has_creation and not has_boundary:
            findings.append(self._create_finding(
                message="Policy allows user/role creation without enforcing permission boundaries",
                affected_resource=policy.name or "Unknown",
                remediation="Add permission boundary requirement to prevent privilege escalation. "
                          "Use: aws:PermissionsBoundary in condition.",
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
            ))
        
        return findings
    
    @staticmethod
    def _matches_pattern(action: str, pattern: str) -> bool:
        """Check if action matches a permission pattern."""
        regex = pattern.replace("*", ".*").replace(":", r"\:")
        return bool(re.match(f"^{regex}$", action, re.IGNORECASE))


class UnencryptedDataAccessCheck(PolicyCheck):
    """Detect permissions for unencrypted data access."""
    
    check_id = "IAM-009"
    check_name = "Unencrypted Data Access Allowed"
    description = "Policy allows access without encryption enforcement"
    severity = Severity.MEDIUM
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # Check for S3 access without encryption requirement
        has_s3_access = any("s3" in action.lower() for action in policy.actions)
        
        # Check if encryption is required
        has_encryption_requirement = any(
            "encrypt" in str(cond).lower() or "ssl" in str(cond).lower()
            for cond in policy.conditions.values()
        )
        
        if has_s3_access and not has_encryption_requirement:
            findings.append(self._create_finding(
                message="S3 access policy does not enforce encryption in transit",
                affected_resource=policy.name or "Unknown",
                remediation="Require SSL/TLS by adding condition: "
                          '"aws:SecureTransport": "true"',
                reference="https://docs.aws.amazon.com/AmazonS3/latest/dev/security_iam_service-with-iam.html"
            ))
        
        return findings


class DeprecatedApiCheck(PolicyCheck):
    """Detect permissions for deprecated or legacy APIs."""
    
    check_id = "IAM-010"
    check_name = "Deprecated API Usage"
    description = "Policy allows access to deprecated or legacy APIs"
    severity = Severity.LOW
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        deprecated_actions = [
            "iam:GetLoginProfile",  # Use console access via federated identity
            "iam:CreateAccessKey",  # Use temporary credentials
            "acm:DescribeCertificate",  # Certificate details exposed
        ]
        
        for action in policy.actions:
            if action in deprecated_actions:
                findings.append(self._create_finding(
                    message=f"Policy allows deprecated action: {action}",
                    affected_resource=policy.name or "Unknown",
                    remediation=f"Replace deprecated action with modern alternative. "
                              f"Consider using AWS STS for temporary credentials.",
                    details={"deprecated_action": action}
                ))
        
        return findings


class ResourceTagCheck(PolicyCheck):
    """Detect policies that don't consider resource tags for access control."""
    
    check_id = "IAM-011"
    check_name = "No Resource Tag-Based Access Control"
    description = "Policy lacks tag-based conditions for fine-grained access"
    severity = Severity.MEDIUM
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # Check if resource tag conditions are present
        has_tag_condition = any(
            "tag" in str(cond).lower()
            for cond in policy.conditions.values()
        )
        
        # Check if this is a high-privilege policy
        high_privilege_actions = [
            "ec2:RunInstances",
            "rds:CreateDBInstance",
            "dynamodb:CreateTable",
        ]
        
        has_high_privilege = any(
            any(self._matches_pattern(a, hpa) for hpa in high_privilege_actions)
            for a in policy.actions
        )
        
        if has_high_privilege and not has_tag_condition:
            findings.append(self._create_finding(
                message="High-privilege policy lacks tag-based access control",
                affected_resource=policy.name or "Unknown",
                remediation="Add resource tag conditions to limit access to specific resource types. "
                          'Example: "ec2:ResourceTag/environment": "prod"',
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_iam-tags.html"
            ))
        
        return findings
    
    @staticmethod
    def _matches_pattern(action: str, pattern: str) -> bool:
        """Check if action matches a permission pattern."""
        regex = pattern.replace("*", ".*").replace(":", r"\:")
        return bool(re.match(f"^{regex}$", action, re.IGNORECASE))


class DenyPolicyMissingCheck(PolicyCheck):
    """Detect policies that should use explicit Deny statements."""
    
    check_id = "IAM-012"
    check_name = "No Explicit Deny Statements"
    description = "Policy lacks explicit Deny statements for dangerous actions"
    severity = Severity.LOW
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # This check is more informational - encourage deny-first thinking
        if policy.effect and policy.effect.upper() == "ALLOW":
            findings.append(self._create_finding(
                message="Policy only contains Allow statements, no explicit Denies",
                affected_resource=policy.name or "Unknown",
                remediation="Consider adding explicit Deny policies for dangerous actions. "
                          "Deny always takes precedence and is more explicit about security boundaries.",
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"
            ))
        
        return findings
