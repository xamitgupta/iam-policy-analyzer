# Contributing to IAM Policy Analyzer

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing.

## 🎯 How to Contribute

### Reporting Bugs

Found a bug? Please create an issue with:

1. Clear title describing the bug
2. Steps to reproduce
3. Expected behavior
4. Actual behavior
5. Your environment (Python version, OS, etc.)

### Suggesting Features

Have a great idea? We'd love to hear it! Create an issue with:

1. Clear title and description
2. Why you think this feature would be useful
3. Possible implementation approach (if you have one)

### Adding Security Checks

This is a great way to contribute! Here's how:

1. **Create a new check class** in `iam_policy_analyzer/security_checks.py`:

```python
class MyNewCheck(PolicyCheck):
    check_id = "IAM-XXX"  # Use next available number
    check_name = "Clear Name"
    description = "What this check detects"
    severity = Severity.HIGH  # CRITICAL, HIGH, MEDIUM, LOW, or INFO
    
    def analyze(self, policy: PolicyDocument) -> List[Finding]:
        findings = []
        
        # Your check logic here
        if violation_detected:
            findings.append(self._create_finding(
                message="What the violation is",
                affected_resource=policy.name or "Unknown",
                remediation="How to fix it",
                reference="Link to docs/AWS docs"
            ))
        
        return findings
```

2. **Register the check** in `IAMAnalyzer._register_checks()`:

```python
def _register_checks(self) -> None:
    checks = [
        # ... existing checks ...
        MyNewCheck(),  # Add yours here
    ]
```

3. **Test it** with the example policies:
```bash
iam-analyzer analyze examples/bad-policy-wildcards.json
```

4. **Update README.md** with your new check in the check reference table

5. **Create a pull request** with your changes

### Code Style

- Follow PEP 8
- Use type hints
- Add docstrings to functions/classes
- Keep functions focused and testable

### Testing

Before submitting a PR:

```bash
# Run tests
pytest

# Check code style
black --check iam_policy_analyzer/
ruff check iam_policy_analyzer/

# Type checking
mypy iam_policy_analyzer/
```

## 🔄 Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Test thoroughly
5. Commit with clear messages: `git commit -m "Add: description"`
6. Push to your fork
7. Create a Pull Request with:
   - Clear title and description
   - Reference to related issues
   - What you changed and why

## 📝 Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat: Add Okta policy parser

- Implement PolicyParser._parse_okta()
- Support rules and group extraction
- Add example Okta policy file

Closes #42
```

## 🚀 Development Setup

```bash
# Clone the repo
git clone https://github.com/xamitgupta/iam-policy-analyzer.git
cd iam-policy-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pre-commit install
```

## 📚 Documentation

- Update README.md if changing user-facing behavior
- Update docstrings for code changes
- Add examples if introducing new features

## 🎓 Learning Resources

- [AWS IAM Documentation](https://docs.aws.amazon.com/iam/)
- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [OWASP IAM Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

## 💬 Questions?

- Check existing [GitHub Issues](https://github.com/xamitgupta/iam-policy-analyzer/issues)
- Start a [Discussion](https://github.com/xamitgupta/iam-policy-analyzer/discussions)
- Email: apphelp.csw@gmail.com

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to make IAM security better for everyone!** 🙏
