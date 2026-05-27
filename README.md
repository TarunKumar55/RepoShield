# 🛡️ RepoShield: Zero-Trust Git Protection

**RepoShield** is a modern, high-performance CLI tool designed to protect developers from malicious repositories. It intercepts `git clone` commands and routes them through an isolated, containerized security sandbox **before they ever touch your host machine** — automatically scoring, deciding, and blocking based on a configurable policy engine.

![Gradient Banner](https://img.shields.io/badge/Aesthetic-Immersive_CLI-cyan)
![Security](https://img.shields.io/badge/Security-Zero--Trust-purple)
![Docker](https://img.shields.io/badge/Backend-Docker_Sandbox-blue)
![Tests](https://img.shields.io/badge/Tests-109%20Passing-brightgreen)

---

## ✨ Features

### 🏗️ Two-Container Zero-Trust Architecture
- **Cloner Container** — pulls the repository into an ephemeral Docker volume (network enabled).
- **Scanner Container** — mounts the volume **read-only**, operates with `network_disabled=True`, memory caps, CPU limits, and dropped privileges. No scanner can call home or exfiltrate data.

### 🔍 5-Engine Parallel Scanning
All five scanners run concurrently via multithreading for maximum speed:

| Engine | What It Catches |
|--------|----------------|
| **Gitleaks** | Hardcoded secrets, API keys, tokens |
| **Semgrep** | SAST vulnerabilities (SQLi, XSS, command injection, etc.) |
| **Bandit** | Python-specific security issues (CWE-mapped) |
| **Hook Scanner** *(custom)* | Malicious install hooks (`setup.py`, `package.json`, GitHub Actions, Makefiles) |
| **Anomaly Scanner** *(custom)* | Binary executables, committed credentials, polyglot files, oversized files |

### 🎯 Risk Scoring Engine
Every scan produces a single **0.0–10.0 risk score** using:
- Weighted severity (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=0.5)
- Confidence multipliers per finding
- Type diversity bonus (secrets + SAST + anomaly = higher risk than all-of-one-type)
- Logarithmic normalization (never inflated by sheer volume)

### ✅ Policy Engine — PASS / WARN / FAIL
Configurable hard-block rules evaluated after every scan:
- `block_on_secrets` — **FAIL** on any secret detection regardless of score (default: `true`)
- `block_on_critical` — **FAIL** on any CRITICAL-severity finding (default: `true`)
- `risk_threshold` — **FAIL** if score exceeds threshold (default: `5.0`)
- Scores below threshold with findings → **WARN** (user decides)
- No findings → **PASS** (auto-clone)

### 📊 Reporting
- **Terminal Table** — instant breakdown of findings by Severity, Category, and Description
- **Sanitized HTML Report** — XSS-protected audit dashboard, auto-opens in browser
- **JSON Export** — full `ScanResult` model for integration into other tools
- **Structured Logs** — JSON event logs written to `~/.reposhield/logs/YYYY-MM-DD.jsonl` with unique `run_id` per scan

### 🤖 CI/CD Ready
```bash
# Non-interactive, machine-readable output
reposhield clone <url> --output json --auto

# Exit codes: 0=PASS  1=FAIL/BLOCKED  2=scanner error  3=invalid input
```

### ⚙️ Configurable Policies
```bash
reposhield configure
```
- Set `risk_threshold`, `block_on_secrets`, `block_on_critical`
- Ignore specific severities or scanner categories
- Config stored in `~/.reposhield/config.json`

---

## 🚀 Getting Started

### Prerequisites
- **Docker Desktop** must be running
- Windows (PowerShell) — Linux/macOS support planned

### Installation

1. Download `reposhield.exe` from the [latest release](https://github.com/Dealer-09/RepoShield-CLI/releases).
2. Open PowerShell and run:
   ```powershell
   .\reposhield.exe install
   ```
3. Restart your terminal — `git clone` is now intercepted automatically.

### Uninstallation
```powershell
.\reposhield.exe uninstall
```
Removes the PowerShell interceptor, deletes config files, and optionally removes the Docker image.

---

## 📖 Usage

### Automatic interception (after `install`)
```powershell
git clone https://github.com/some/repo
```

### Direct usage
```powershell
# Interactive (default)
reposhield clone https://github.com/some/repo

# CI/CD pipeline (non-interactive, JSON output)
reposhield clone https://github.com/some/repo --output json --auto

# Configure security policy
reposhield configure
```

### Example output
```
◇ 🛡️  Initializing Secure Sandbox for: https://github.com/OWASP/NodeGoat
│ ⏳ Pulling isolated scanner container and analyzing...
◇ ⚠️  Issues Found! Found 3 Secret, 1 SAST finding.
│ Risk Score: 10.0/10.0  Verdict: FAIL
│ BLOCKED: Risk score 10.0/10.0 exceeds threshold 5.0.
│ 🚫 Clone aborted. Your machine remains safe.
```

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|-----------|
| CLI Engine | [Typer](https://typer.tiangolo.com/) (Python) |
| UI Framework | [Rich](https://github.com/Textualize/rich) |
| Containerization | [Docker SDK for Python](https://docker-py.readthedocs.io/) |
| Data Models | [Pydantic](https://docs.pydantic.dev/) |
| Secret Detection | [Gitleaks v8.21.2](https://github.com/gitleaks/gitleaks) |
| SAST | [Semgrep 1.90.0](https://semgrep.dev/) |
| Python SAST | [Bandit 1.7.10](https://bandit.readthedocs.io/) |
| Custom Scanners | hook_scanner.py, anomaly_scanner.py |

---

## 🔐 Zero-Trust Philosophy

RepoShield treats every remote repository as potentially compromised. The full pipeline is:

```
CLONE → SCAN (5 engines, air-gapped) → RISK SCORE → POLICY → PASS/WARN/FAIL → ALLOW/BLOCK
```

**Core security pillars:**
- **Protocol Enforcement** — Only `https://` and `git@` permitted. File paths and injection attempts are blocked.
- **Network Isolation** — Scanner container runs with `network_disabled=True`. Cannot call home even if a scanner tool is compromised.
- **Immutable Sandbox** — Read-only filesystem, dropped privileges, non-root user (`scanner_user`).
- **Resource Jailing** — CPU (0.5 cores), Memory (512MB) caps prevent zip bomb and resource exhaustion attacks.
- **Air-Gapped Rules** — All Semgrep rules are baked into the Docker image at build time. Zero network required for scanning.
- **Deterministic Deduplication** — Each finding has a content-hash ID, eliminating duplicate noise across runs.

---

## 📁 Storage Layout

```
~/.reposhield/
├── config.json          # Security policy configuration
├── reports/             # HTML + JSON audit reports
│   └── report_YYYYMMDD_HHMMSS.html
└── logs/                # Structured JSON event logs
    └── YYYY-MM-DD.jsonl
```

---

*Built by [Dealer-09](https://github.com/Dealer-09) for a safer open-source ecosystem.*  
*Based on [Reposhield-V2](https://github.com/rajdeep13-coder/Reposhield-V2) by [rajdeep13-coder](https://github.com/rajdeep13-coder) & [extremecoder-rgb](https://github.com/extremecoder-rgb)*