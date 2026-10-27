# Contributing to phpArchangel

First off, thank you for considering contributing to phpArchangel!

Community contributions help make open-source security tools more reliable, accessible, and effective.

## How Can I Contribute?

### Reporting Bugs

- Search existing GitHub Issues before opening a new report.
- If the issue has not been reported, open a new issue.
- Include a clear title, detailed description, and steps to reproduce.
- Provide relevant logs, environment information, and expected versus actual behavior.
- Include a minimal reproducible example when possible.
- Remove credentials, tokens, and sensitive information from reports.

**Security vulnerabilities must be reported privately. See the Security Disclosures section below.**

### Suggesting Enhancements

- Open a new issue with the `enhancement` label, if available.
- Explain the proposed feature and its intended purpose.
- Describe the expected behavior and potential benefits.
- Include examples or implementation ideas where applicable.

### Pull Requests

1. Fork the repository.
2. Create a feature branch from `main`.
3. Make your changes with clear, focused commits.
4. Add or update tests when appropriate.
5. Run the available validation checks.
6. Update documentation if your changes affect usage.
7. Submit a Pull Request describing your changes.

Before submitting, check Python syntax:

```bash
python3 -m compileall -q src/php_archangel
```

**Note:** Syntax compilation is not a replacement for running the project's actual test suite.

## Development Setup

Clone the repository:

```bash
git clone https://github.com/tarbo03/phpArchangel.git
cd phpArchangel
```

Create and activate a virtual environment:

**Linux / macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows PowerShell:**

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
```

Install the project in editable mode:

```bash
python -m pip install -e .
```

This requires a compatible Python packaging configuration.

## Security Disclosures

Please do **not** disclose security vulnerabilities through public GitHub Issues or Discussions.

Refer to [SECURITY.md](SECURITY.md) for the project's private vulnerability disclosure instructions.

## Code of Conduct

Contributors are expected to communicate respectfully, collaborate constructively, and follow responsible security research practices.

Thank you for helping improve phpArchangel!
