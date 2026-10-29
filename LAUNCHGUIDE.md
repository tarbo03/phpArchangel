# phpArchangel MCP Server Launch Guide

## Overview

`phpArchangel` is a precision-first PHP vulnerability scanner. It is built to detect and verify exposure to the `php2shell` CVE class (CVE-2026-109618 / CVE-2026-109619).

Unlike traditional scanners that guess based on headers, `phpArchangel` requires deterministic physical proof before declaring a target vulnerable.

It follows the **SecPipe Doctrine: Zero False Positives by Design**.

## Installation

**PyPI Package:** https://pypi.org/project/php-archangel-mcp/

Install using pip:

```bash
pip install php-archangel-mcp
```

## MCP Features Exposed

Once connected, AI agents such as Claude Desktop or Cursor can use the following tools:

1. **`scan_target`**: Performs a non-destructive reconnaissance sweep. Returns PROBABLE verdicts with supporting evidence chains.

2. **`confirm_cve`**: Runs a deterministic OOM or Worker-Affinity oracle to confirm or retract a suspected vulnerability.

3. **`get_evidence`**: Returns full JSON evidence chains for a completed scan.

4. **`report`**: Generates a colorized Markdown report.

5. **`exploit_target` **: An opt-in, gated RCE proof-of-concept using the Angel-Sword chain. **Disabled by default.** Requires explicit operator consent and the `--allow-exploit` flag.

## Use Cases

### Automated Threat Hunting
Ask Claude to scan authorized internal PHP servers and summarize which ones are vulnerable.

### Zero False Positive Auditing
Use the verification oracle to determine whether a suspected CVE is genuinely exploitable or merely a false positive produced by version headers.

### Red Team Reconnaissance
Perform automated, non-destructive reconnaissance of authorized targets before human operators proceed with further testing.


## Server Configuration

To configure this MCP server in Claude Desktop, add the following entry to your MCP configuration file:

```json
{
  "mcpServers": {
    "phpArchangel": {
      "command": "php-archangel-mcp",
      "args": ["mcp"]
    }
  }
}
```

Ensure that the MCP package is installed and its executable is available in your system PATH.

## Security Philosophy

**Zero False Positives by Design**

phpArchangel prioritizes verified evidence over speculative vulnerability detection.

Its core principles include:

- Evidence-first vulnerability assessment
- Deterministic verification
- Non-destructive reconnaissance by default
- Transparent, reproducible evidence chains
- Explicit authorization for active exploitation
- Human oversight for high-risk operations

The objective is to minimize false positives and provide trustworthy vulnerability intelligence.

## Marketplace Search Tags

`security`, `vulnerability-scanner`, `php`, `pentesting`, `cybersecurity`, `red-team`, `rce`, `evidence-based`, `zero-false-positives`, `mcp`, `ai-security`

