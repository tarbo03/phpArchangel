# php_Archangel

**PHP runtime security posture analyzer** — detects the php2shell
vulnerabilities (CVE-2026-109618 / CVE-2026-109619), fingerprints PHP
versions on hardened targets, enumerates embedded PHP components, and
reports patch-floor deficits — with AI-assisted triage, evidence-gated
verdicts, and an MCP-server face for agentic operation.

Built on one principle: **if the tool cannot prove a finding is real, it
does not report it as fact.** Unverified suspicions surface as PROBABLE or
RETRACTED — with reasons, never hidden.

## Capabilities

- **CVE-2026-109618**: deliberate OOM against a live worker; two-step
  producer/consumer oracle — vulnerable = worker abort signature, patched =
  graceful failure at both steps
- **CVE-2026-109619**: same-worker producer/consumer via pinned keep-alive
  plus session upload-progress primitives
- **PHP discovery**: headers, easter-egg image-hash corpus (narrow version
  bands), credits-era dating, error-text banding, changelog-delta probes
- **Hidden PHP and components**: composer.json/lock ground truth, WordPress
  / Drupal / Joomla / Magento fingerprints, plugin readme.txt enumeration,
  exposed vendor trees, JS-bundle endpoint and plugin-path analysis
- **Patch-floor analysis**: flags CVE-pending memory-safety fixes behind your
  version — including 8.4.27/8.3.36/8.2.35 backport branches that fixed only
  the two GHSAs
- **Zero-CVE window**: detects vulnerabilities from the moment the fix lands
  in the changelog — before a CVE number exists
- **Exploit (authorized use)**: full angel-sword weapon, ASLR bypass via
  two-stage leaks, fake-reference pDestructor hijack; opt-in gated
- **AI triage**: OpenRouter (default) / NVIDIA (free model
  `deepseek-v4.1-flash`) / Anthropic / OpenAI; severity-capped in
  code, sees only structured evidence
- **MCP server**: stdio (Claude Desktop / Cursor / Cline) + Streamable
  HTTP with bearer auth; exploit tool dual-gated with `--allow-exploit`

## Install

    pip install -e .                 # core
    pip install -e ".[ai]"           # AI providers
    pip install -e ".[mcp]"          # MCP server
    pip install -e ".[browser]"      # optional Playwright tier

## Quick start

    php_archangel scan                       # interactive
    php_archangel scan https://target.com    # direct
    php_archangel scan https://t.com --auto-confirm   # CI mode
    php_archangel report findings.json --output report.md
    php_archangel mcp                        # MCP stdio
    php_archangel mcp --http --allow-exploit # remote, weapon armed

Safe by default (PROBABLE verdicts, no crash risk). Confirmation and
exploitation prompt the user; a vulnerable worker may crash during
confirmation — it auto-restarts.

## Verdict discipline

CONFIRMED / PROBABLE / RETRACTED (with reason, never hidden) / CLEAN.
Output: findings.json and report.md per target in ./archangel-out/.

## Lab validation

See lab/VALIDATE.md:

    cd lab && docker compose up -d
    php_archangel scan http://127.0.0.1:8088/index.php --auto-confirm
    php_archangel scan http://127.0.0.1:8089/index.php --auto-confirm

## AI keys

    export OPENROUTER_API_KEY=...   # default provider
    export NVIDIA_API_KEY=...       # free testing model

AI is optional; without keys the tool runs fully deterministic. Spend is
capped (10 calls / 25K tokens per scan) and never blocks output.

## Integrity

Authorized security testing tool. The exploit module executes commands on
targets and is always opt-in. Get permission before scanning what you
don't own.

## Setting your AI keys (one-time)

    php_archangel config

Interactive: paste one or more of OpenRouter / NVIDIA / Anthropic / OpenAI
keys. Stored in ~/.config/php_archangel/keys (chmod 600). To test free:

- Get an NVIDIA key at build.nvidia.com (free)
- php_archangel config -> paste it under NVIDIA
- scans now use deepseek-v4.1-flash at zero cost

Environment variables (OPENROUTER_API_KEY etc.) override the file —
use those for CI/automation. php_archangel config --show to inspect.

### Choosing a model
Default triage model is fast (non-reasoning). For deeper narrative analysis:
php_archangel report findings.json --ai-model deepseek-ai/deepseek-v4.1-flash
(expect longer runtimes — it reasons before answering; give it max-token headroom)
