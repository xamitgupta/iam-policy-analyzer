# 🔒 IAM Policy Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Automated security analysis for IAM policies across cloud providers and identity systems.**

Every organization has IAM policies full of vulnerabilities, conflicts, and dead code. Most organizations don't know about them until something breaks—or worse, until a security incident. This tool finds them in seconds.

![Screenshot](docs/example-output.txt)

## 🎯 What It Does

IAM Policy Analyzer automatically scans your policies and reports:

- **Wildcard permissions** that violate least privilege
- **Admin access** granted to non-admin users
- **Sensitive actions without MFA** (e.g., DeleteUser, DisableKey)
- **Missing security boundaries** that enable privilege escalation
- **Hardcoded credentials** that could leak secrets
- **Over-permission** that should be restricted
- **Deprecated APIs** you should migrate away from
- **And 12+ more checks** covering common IAM mistakes

## ⚡ Quick Start

### Install

```bash
pip install iam-policy-analyzer
```

Or from source:
```bash
git clone https://github.com/xamitgupta/iam-policy-analyzer.git
cd iam-policy-analyzer
pip install -e .
```

### Analyze a Policy

```bash
# Analyze a single policy
iam-analyzer analyze my-policy.json

# Filter by severity
iam-analyzer analyze policy.yaml --min-severity HIGH

# Show detailed findings
iam-analyzer analyze policy.json --details

# Export as JSON
iam-analyzer analyze policy.json --format json > results.json

# Analyze entire directory
iam-analyzer batch ./policies/ --output results.json
```

## 📊 Example Output

```
╔═══════════════════════════════════════════════════════╗
║   🔒 IAM Policy Analyzer                              ║
║   Automated security analysis for identity policies   ║
╚═══════════════════════════════════════════════════════╝

Analyzing: example-policy.json

📊 Analysis Summary
Total Findings        3
CRITICAL              1
HIGH                  2
MEDIUM                0
LOW                   0
INFO                  0

🔍 Findings (3)

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 1. CRITICAL                                          ┃
┃                                                       ┃
┃ ID: IAM-002                                          ┃
┃ Name: Wildcard Action Detected                       ┃
┃ Resource: AdminRole                                  ┃
┃                                                       ┃
┃ Issue:                                               ┃
┃ Policy allows all actions (*), granting excessive    ┃
┃ permissions                                          ┃
┃                                                       ┃
┃ Remediation:                                         ┃
┃ Replace wildcard actions with specific, necessary    ┃
┃ permissions. Example: Use 's3:GetObject' instead     ┃
┃ of 's3:*'                                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## 🔐 Supported Checks

| Check ID | Name | Severity | Description |
|----------|------|----------|-------------|
| IAM-001 | Wildcard Principal | CRITICAL | Policy grants access to all principals (*) |
| IAM-002 | Wildcard Action | CRITICAL | Policy allows all actions (*) |
| IAM-003 | Wildcard Resource | HIGH | Policy grants access to all resources (*) |
| IAM-004 | Admin Access | CRITICAL | Policy grants administrative permissions |
| IAM-005 | Missing MFA | HIGH | Sensitive actions without MFA requirement |
| IAM-006 | Credential Exposure | CRITICAL | Hardcoded credentials detected |
| IAM-007 | Overly Permissive PassRole | HIGH | PassRole without resource restrictions |
| IAM-008 | No Permission Boundary | MEDIUM | Missing permission boundary enforcement |
| IAM-009 | Unencrypted Data Access | MEDIUM | S3 access without encryption requirement |
| IAM-010 | Deprecated API | LOW | Usage of deprecated/legacy APIs |
| IAM-011 | No Resource Tags | MEDIUM | Missing tag-based access control |
| IAM-012 | No Deny Statements | LOW | Policy lacks explicit Deny statements |

## 📋 Supported Formats

- **AWS IAM** - Policy documents, inline policies, managed policies
- **Okta** - Access policies and rules
- **Azure AD** - Role definitions and permission assignments
- **GCP** - IAM policies and custom roles
- **Generic JSON/YAML** - Flexible structure for custom systems

## 🚀 Advanced Usage

### Integrate with CI/CD

```yaml
# GitHub Actions example
- name: Analyze IAM Policies
  uses: xamitgupta/iam-policy-analyzer@v0.1.0
  with:
    policy-dir: ./policies/
    fail-on-critical: true
```

### Python API

```python
from iam_policy_analyzer import IAMAnalyzer

analyzer = IAMAnalyzer()

# Analyze a file
result = analyzer.analyze_file("my-policy.json")

# Check findings
for finding in result.findings:
    print(f"{finding.severity}: {finding.message}")
    print(f"Remediation: {finding.remediation}")

# Filter by severity
critical_findings = [f for f in result.findings 
                     if f.severity == Severity.CRITICAL]
```

### Custom Checks

Extend the analyzer with your own security checks:

```python
from iam_policy_analyzer.checks import PolicyCheck
from iam_policy_analyzer.models import Finding, Severity

class MyCustomCheck(PolicyCheck):
    check_id = "CUSTOM-001"
    check_name = "My Custom Check"
    severity = Severity.MEDIUM
    
    def analyze(self, policy):
        findings = []
        # Your check logic here
        if some_violation:
            findings.append(self._create_finding(
                message="Your message",
                affected_resource=policy.name,
                remediation="How to fix it"
            ))
        return findings
```

## 📈 Real-World Examples

### Example 1: Admin Policy with Wildcards

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "*",
    "Resource": "*"
  }]
}
```

**Findings:**
- ❌ IAM-001: Wildcard Principal (CRITICAL)
- ❌ IAM-002: Wildcard Action (CRITICAL)  
- ❌ IAM-003: Wildcard Resource (HIGH)

**Remediation:** Specify exact principals, actions, and resources.

### Example 2: Sensitive Actions Without MFA

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:user/bob"},
    "Action": "iam:DeleteUser",
    "Resource": "*"
  }]
}
```

**Findings:**
- ❌ IAM-005: Sensitive Action Without MFA (HIGH)

**Remediation:** Add MFA requirement to the condition.

## 🤝 Contributing

Contributions are welcome! Areas to help:

- Adding new security checks
- Supporting additional policy formats
- Improving documentation
- GitHub Actions integration
- Bug reports and feature requests

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📚 Documentation

- [Installation Guide](docs/INSTALL.md)
- [User Guide](docs/GUIDE.md)
- [Check Reference](docs/CHECKS.md)
- [API Documentation](docs/API.md)
- [Contributing Guide](CONTRIBUTING.md)

## 🔗 Resources

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Okta Policy Documentation](https://developer.okta.com/docs/reference/api/policy/)
- [Azure AD Role Security](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning)
- [GCP IAM Security](https://cloud.google.com/iam/docs/best-practices)

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 👨‍💻 Author

**Amit Gupta**
- Staff Security Engineer @ Meta
- OSAC Panelist
- [Twitter](https://x.com/_xamitgupta)
- [LinkedIn](https://linkedin.com/in/yourprofile)

---

**Found an issue?** [Report it on GitHub](https://github.com/xamitgupta/iam-policy-analyzer/issues)

**Have an idea?** [Start a discussion](https://github.com/xamitgupta/iam-policy-analyzer/discussions)

**Like this tool?** Please ⭐ star the repo!
