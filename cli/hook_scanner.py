"""
Install Hook & CI/CD Poisoning Scanner for RepoShield.
Detects malicious patterns in setup.py, package.json, Makefile, and GitHub Actions.
Runs inside the air-gapped scanner container — no external dependencies.

Usage: python hook_scanner.py <repo_dir> <output_json>
"""
import os
import re
import sys
import json
import glob


# ── Dangerous patterns by file type ──────────────────────────────────────────

PYTHON_INSTALL_PATTERNS = [
    # System command execution
    (r'\bos\.system\s*\(', "CRITICAL", "os.system() call in install script"),
    (r'\bos\.popen\s*\(', "CRITICAL", "os.popen() call in install script"),
    (r'\bsubprocess\.\w+\s*\(', "CRITICAL", "subprocess call in install script"),
    (r'\beval\s*\(', "CRITICAL", "eval() call in install script"),
    (r'\bexec\s*\(', "CRITICAL", "exec() call in install script"),
    (r'\b__import__\s*\(', "HIGH", "__import__() dynamic import in install script"),
    (r'\bcompile\s*\(.*exec', "HIGH", "compile() with exec mode in install script"),
    # Network access from install script
    (r'\burllib\.request', "HIGH", "Network access (urllib) in install script"),
    (r'\brequests\.get\s*\(', "HIGH", "Network access (requests.get) in install script"),
    (r'\burlopen\s*\(', "HIGH", "Network access (urlopen) in install script"),
    (r'\bsocket\.', "HIGH", "Socket access in install script"),
    # Obfuscation indicators
    (r'base64\.b64decode', "MEDIUM", "Base64 decoding in install script — possible obfuscation"),
    (r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}', "MEDIUM", "Hex-encoded strings in install script"),
]

# Files where Python install patterns are dangerous
PYTHON_INSTALL_FILES = ["setup.py", "setup.cfg", "conftest.py"]

NPM_SCRIPT_PATTERNS = [
    # Dangerous script hooks
    (r'"(preinstall|postinstall|preuninstall|postuninstall|prepare|prepublish|prepublishOnly)"\s*:', "hooks", None),
]

NPM_DANGEROUS_COMMANDS = [
    (r'\bcurl\b', "CRITICAL", "curl in npm install hook"),
    (r'\bwget\b', "CRITICAL", "wget in npm install hook"),
    (r'\bbash\b', "HIGH", "bash execution in npm install hook"),
    (r'\bsh\s+-c\b', "HIGH", "sh -c execution in npm install hook"),
    (r'\bnode\s+-e\b', "HIGH", "node -e inline execution in npm install hook"),
    (r'\beval\b', "HIGH", "eval in npm install hook"),
    (r'\bpowershell\b', "HIGH", "powershell execution in npm install hook"),
    (r'https?://', "MEDIUM", "URL reference in npm install hook"),
]

GITHUB_ACTIONS_PATTERNS = [
    # Expression injection — user-controlled values interpolated into shell
    (r'\$\{\{\s*github\.event\.issue\.title', "CRITICAL", "GitHub Actions injection via issue title"),
    (r'\$\{\{\s*github\.event\.issue\.body', "CRITICAL", "GitHub Actions injection via issue body"),
    (r'\$\{\{\s*github\.event\.pull_request\.title', "CRITICAL", "GitHub Actions injection via PR title"),
    (r'\$\{\{\s*github\.event\.pull_request\.body', "CRITICAL", "GitHub Actions injection via PR body"),
    (r'\$\{\{\s*github\.event\.comment\.body', "CRITICAL", "GitHub Actions injection via comment body"),
    (r'\$\{\{\s*github\.event\.review\.body', "CRITICAL", "GitHub Actions injection via review body"),
    (r'\$\{\{\s*github\.event\.pages\.\*\.page_name', "HIGH", "GitHub Actions injection via page name"),
    (r'\$\{\{\s*github\.head_ref\b', "HIGH", "GitHub Actions injection via head_ref"),
    (r'\$\{\{\s*inputs\.', "MEDIUM", "GitHub Actions expression with user input"),
]

MAKEFILE_PATTERNS = [
    (r'\$\(shell\s+curl\b', "CRITICAL", "curl execution in Makefile shell"),
    (r'\$\(shell\s+wget\b', "CRITICAL", "wget execution in Makefile shell"),
    (r'curl\s+.*\|\s*(ba)?sh', "CRITICAL", "curl piped to shell in Makefile"),
    (r'wget\s+.*\|\s*(ba)?sh', "CRITICAL", "wget piped to shell in Makefile"),
]


def scan_file_patterns(filepath, content, patterns):
    """Scan file content against a list of (regex, severity, description) patterns."""
    findings = []
    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        for pattern, severity, description in patterns:
            if re.search(pattern, line):
                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "severity": severity,
                    "description": description,
                    "match": line.strip()[:120],
                })
    return findings


def scan_python_install_files(repo_dir):
    """Scan setup.py and related files for dangerous install hooks."""
    findings = []
    for filename in PYTHON_INSTALL_FILES:
        filepath = os.path.join(repo_dir, filename)
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                findings.extend(scan_file_patterns(filename, content, PYTHON_INSTALL_PATTERNS))
            except Exception:
                pass
    return findings


def scan_package_json(repo_dir):
    """Scan package.json for dangerous install hook scripts."""
    findings = []
    filepath = os.path.join(repo_dir, "package.json")
    if not os.path.exists(filepath):
        return findings

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        scripts = data.get("scripts", {})
        dangerous_hooks = ["preinstall", "postinstall", "preuninstall",
                           "postuninstall", "prepare", "prepublish", "prepublishOnly"]

        for hook in dangerous_hooks:
            if hook in scripts:
                script_value = scripts[hook]
                # Check the hook command against dangerous patterns
                for pattern, severity, description in NPM_DANGEROUS_COMMANDS:
                    if re.search(pattern, script_value):
                        findings.append({
                            "file": "package.json",
                            "line": None,
                            "severity": severity,
                            "description": f"{description} ({hook})",
                            "match": f'"{hook}": "{script_value[:100]}"',
                        })
    except (json.JSONDecodeError, Exception):
        pass

    return findings


def scan_github_actions(repo_dir):
    """Scan GitHub Actions workflow files for expression injection."""
    findings = []
    workflow_dir = os.path.join(repo_dir, ".github", "workflows")
    if not os.path.isdir(workflow_dir):
        return findings

    for yml_file in glob.glob(os.path.join(workflow_dir, "*.yml")) + \
                     glob.glob(os.path.join(workflow_dir, "*.yaml")):
        try:
            with open(yml_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            rel_path = os.path.relpath(yml_file, repo_dir).replace("\\", "/")
            findings.extend(scan_file_patterns(rel_path, content, GITHUB_ACTIONS_PATTERNS))
        except Exception:
            pass

    return findings


def scan_makefiles(repo_dir):
    """Scan Makefiles for dangerous shell patterns."""
    findings = []
    for name in ["Makefile", "makefile", "GNUmakefile"]:
        filepath = os.path.join(repo_dir, name)
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                findings.extend(scan_file_patterns(name, content, MAKEFILE_PATTERNS))
            except Exception:
                pass
    return findings


def main():
    if len(sys.argv) < 3:
        print("Usage: python hook_scanner.py <repo_dir> <output_json>", file=sys.stderr)
        sys.exit(1)

    repo_dir = sys.argv[1]
    output_file = sys.argv[2]

    all_findings = []
    all_findings.extend(scan_python_install_files(repo_dir))
    all_findings.extend(scan_package_json(repo_dir))
    all_findings.extend(scan_github_actions(repo_dir))
    all_findings.extend(scan_makefiles(repo_dir))

    with open(output_file, "w") as f:
        json.dump(all_findings, f)


if __name__ == "__main__":
    main()
