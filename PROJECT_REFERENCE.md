# Project Structure & Quick Reference

## 📁 Directory Layout

```
iam-policy-analyzer/
├── iam_policy_analyzer/           # Main package
│   ├── __init__.py                # Package exports
│   ├── models.py                  # Data models (Finding, Severity, etc)
│   ├── checks.py                  # Base PolicyCheck class
│   ├── security_checks.py         # 12 concrete security checks
│   ├── analyzer.py                # PolicyParser & IAMAnalyzer engine
│   └── cli.py                     # Command-line interface
│
├── examples/                      # Example policies for testing
│   ├── bad-policy-wildcards.json
│   ├── bad-policy-sensitive-no-mfa.json
│   └── good-policy-least-privilege.json
│
├── tests/                         # Unit tests (optional, can add)
│
├── docs/                          # Additional documentation (optional)
│
├── pyproject.toml                 # Project configuration & dependencies
├── README.md                      # User-facing documentation
├── CONTRIBUTING.md                # Contribution guidelines
├── LICENSE                        # MIT License
├── Dockerfile                     # Container image
├── .gitignore                     # Git ignore rules
└── GITHUB_LAUNCH_GUIDE.md         # This launch strategy
```

---

## 🔧 Core Components

### 1. **Models** (`models.py`)
- `Severity` - Enum: CRITICAL, HIGH, MEDIUM, LOW, INFO
- `PolicyType` - Enum: AWS_IAM, OKTA, AZURE_AD, GCP, GENERIC
- `Finding` - Individual violation (check_id, message, remediation, etc)
- `AnalysisResult` - Complete analysis with findings + summary stats
- `PolicyDocument` - Parsed policy with normalized fields

### 2. **Checks Framework** (`checks.py`)
- `PolicyCheck` - Abstract base class for all checks
  - Subclasses implement `analyze(policy) -> List[Finding]`
- `CheckRegistry` - Manages and stores all available checks

### 3. **Security Checks** (`security_checks.py`)
12 concrete checks:
1. `WildcardPrincipalCheck` - Detects Principal: *
2. `WildcardActionCheck` - Detects Action: *
3. `WildcardResourceCheck` - Detects Resource: *
4. `AdminAccessCheck` - Detects iam:*, organizations:*, etc
5. `MissingMFACheck` - Sensitive actions without MFA
6. `CredentialExposureCheck` - Hardcoded credentials
7. `PassAssumeRoleCheck` - iam:PassRole without restrictions
8. `PermissionBoundaryCheck` - Missing boundary enforcement
9. `UnencryptedDataAccessCheck` - S3 without encryption
10. `DeprecatedApiCheck` - Legacy API usage
11. `ResourceTagCheck` - Missing tag-based access control
12. `DenyPolicyMissingCheck` - No explicit Deny statements

### 4. **Analyzer** (`analyzer.py`)
- `PolicyParser` - Parse JSON/YAML into PolicyDocument
  - Auto-detects format
  - Supports AWS IAM, Okta, Azure, GCP, generic
- `IAMAnalyzer` - Main engine
  - Registers all checks
  - Runs them against policies
  - Returns AnalysisResult

### 5. **CLI** (`cli.py`)
Commands:
- `analyze FILE` - Single file analysis
  - Options: `--min-severity`, `--format`, `--details`
- `batch DIR` - Analyze directory of policies
  - Options: `--output FILE`
- `version` - Show version

---

## 🚀 How It Works (Flow)

```
User runs: iam-analyzer analyze policy.json
         ↓
    CLI (cli.py)
         ↓
    PolicyParser.parse_file()
         ↓
    Returns PolicyDocument
         ↓
    IAMAnalyzer.analyze_policy()
         ↓
    For each registered check:
      - Call check.analyze(policy)
      - Collect findings
         ↓
    Return AnalysisResult with:
      - List of Finding objects
      - Summary statistics
         ↓
    CLI formats output:
      - Table (default)
      - JSON
      - CSV
         ↓
    Displays to user
```

---

## 🔧 Adding a New Check (Step-by-Step)

### Step 1: Understand the Pattern

```python
class MyNewCheck(PolicyCheck):
    check_id = "IAM-013"           # Next available number
    check_name = "Check Name"      # Clear, concise
    severity = Severity.HIGH       # CRITICAL/HIGH/MEDIUM/LOW/INFO
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # Check your condition
        if violation_detected:
            findings.append(self._create_finding(
                message="What's wrong",
                affected_resource=policy.name or "Unknown",
                remediation="How to fix it",
                reference="Link to docs",
                details={"extra": "data"}  # Optional
            ))
        
        return findings
```

### Step 2: Implement Your Logic

```python
class UnusedRoleCheck(PolicyCheck):
    check_id = "IAM-013"
    check_name = "Unused Role Detection"
    severity = Severity.MEDIUM
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # Example: detect if role has no actions
        if not policy.actions:
            findings.append(self._create_finding(
                message="Role has no associated actions",
                affected_resource=policy.name or "Unknown",
                remediation="Remove unused roles or assign appropriate actions",
                reference="https://docs.aws.amazon.com/iam/"
            ))
        
        return findings
```

### Step 3: Register in Analyzer

In `analyzer.py`, add to `_register_checks()`:

```python
def _register_checks(self) -> None:
    checks = [
        # ... existing checks ...
        UnusedRoleCheck(),  # ← Add this
    ]
```

### Step 4: Test

```bash
iam-analyzer analyze examples/bad-policy-wildcards.json
```

### Step 5: Update README

Add to the check reference table in README.md

---

## 📊 Output Examples

### Table Format (Default)
```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 1. CRITICAL                           ┃
┃                                       ┃
┃ ID: IAM-002                           ┃
┃ Name: Wildcard Action                 ┃
┃ Resource: AdminRole                   ┃
┃                                       ┃
┃ Issue: Policy allows all actions (*)  ┃
┃                                       ┃
┃ Remediation: Replace with specific    ┃
┃ actions like s3:GetObject              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

### JSON Format
```json
{
  "file": "policy.json",
  "summary": {
    "total": 3,
    "critical": 1,
    "high": 2
  },
  "findings": [
    {
      "check_id": "IAM-002",
      "check_name": "Wildcard Action",
      "severity": "CRITICAL",
      "message": "Policy allows all actions (*)",
      "remediation": "Replace with specific actions"
    }
  ]
}
```

---

## 🧪 Testing

### Run Manually
```bash
# Single file
iam-analyzer analyze examples/bad-policy-wildcards.json

# All examples
iam-analyzer batch examples/

# With options
iam-analyzer analyze examples/bad-policy-sensitive-no-mfa.json \
  --min-severity HIGH \
  --details \
  --format json
```

### Expected Results
- `bad-policy-wildcards.json` → 3 CRITICAL findings
- `bad-policy-sensitive-no-mfa.json` → 3+ findings (HIGH/CRITICAL)
- `good-policy-least-privilege.json` → 0-1 findings (mostly INFO)

---

## 📦 Packaging & Distribution

### PyPI Upload (Optional, for later)
```bash
# Build package
python -m build

# Upload to PyPI
python -m twine upload dist/*

# Install from PyPI
pip install iam-policy-analyzer
```

### Docker
```bash
# Build image
docker build -t iam-analyzer .

# Run analysis
docker run -v $(pwd)/policies:/policies iam-analyzer \
  analyze /policies/my-policy.json
```

---

## 🔄 Development Workflow

### When You Want to Make Changes

```bash
# Create feature branch
git checkout -b feature/new-check

# Make changes
vim iam_policy_analyzer/security_checks.py

# Test
iam-analyzer analyze examples/bad-policy-wildcards.json

# Commit
git add .
git commit -m "feat: Add new security check"

# Push
git push origin feature/new-check

# Create Pull Request on GitHub
```

---

## 📈 Future Enhancement Ideas

**Quick Wins (Next Release):**
- [ ] GitHub Actions integration
- [ ] Terraform validator
- [ ] HTML report generation
- [ ] Custom check plugins

**Medium Term:**
- [ ] CI/CD platform integrations (GitLab, Jenkins)
- [ ] Cloud provider SDKs (boto3, google-cloud, azure)
- [ ] Database schema analyzer
- [ ] Real-time monitoring mode

**Long Term:**
- [ ] Hosted SaaS version
- [ ] Enterprise support
- [ ] ML-based anomaly detection
- [ ] Community policy marketplace

---

## 💡 Pro Tips

1. **Check Order Matters** - Run high-severity checks first (better UX)
2. **Deduplication** - The code dedupes findings automatically
3. **Error Handling** - Individual check failures don't break analysis
4. **Extensibility** - New checks are just new classes, no core changes needed
5. **Performance** - Add check early return if possible to skip expensive logic

---

## 🎯 Key Metrics to Track

When you launch, measure:
- GitHub stars (target: 5K in 3 months)
- PyPI downloads (target: 500/month in 2 months)
- Community issues/PRs (should grow monthly)
- Conference talks/mentions (target: 3+ in 6 months)
- Blog coverage (target: 5+ articles in 3 months)

---

## 📞 Troubleshooting

### "Import error: No module named..."
→ Did you run `pip install -e .`?

### "Policy file not found"
→ Check file path, use absolute path if needed

### "YAML parsing error"
→ Check YAML syntax, use `yamllint policy.yaml`

### "Check returns no findings"
→ Check the policy actually violates that check

---

## 🎓 Resources for Contributors

- [AWS IAM Best Practices](https://docs.aws.amazon.com/iam/latest/userguide/best-practices.html)
- [Okta API Docs](https://developer.okta.com/docs/api/latest/)
- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [OWASP Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

---

**Ready to launch?** 🚀

Follow the GITHUB_LAUNCH_GUIDE.md for step-by-step instructions.

Good luck! 🔒
