import subprocess
import re
import os
import json
from pathlib import Path

# Strict URL pattern matching the one in entrypoint.py for defense-in-depth
URL_PATTERN = re.compile(
    r'^(https://[a-zA-Z0-9._\-]+(/[a-zA-Z0-9._\-]+)*(/[a-zA-Z0-9._\-]+\.git)?/?'
    r'|git@[a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-/]+\.git)$'
)

def is_docker_running() -> bool:
    """Checks if the Docker daemon is running."""
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def validate_repo_url(repo_url: str) -> bool:
    """Validates that the repo URL uses an allowed protocol and character set."""
    return bool(URL_PATTERN.match(repo_url))

def execute_scan(repo_url: str):
    """Executes the security scan via docker, scores risk, and evaluates policy."""
    from scanner import run_scan, parse_findings
    from scoring import calculate_risk_score
    from policy import evaluate_policy
    from config import load_config
    import time

    start = time.time()
    raw_findings = run_scan(repo_url)
    result = parse_findings(raw_findings, repo_url)
    result.scan_duration_seconds = round(time.time() - start, 2)

    # Score risk and evaluate policy
    result.risk_score = calculate_risk_score(result.findings)
    config = load_config()
    result.verdict = evaluate_policy(result, config)

    return result

def generate_report(result) -> str:
    """Generates the HTML report in ~/.reposhield/reports/ and returns its absolute path."""
    from report import generate_html_report
    import datetime

    html_content = generate_html_report(result)

    # Write to a safe, predictable directory instead of CWD
    reports_dir = Path(os.path.expanduser("~")) / ".reposhield" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = reports_dir / f"report_{timestamp}.html"
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return str(report_path)
    
def execute_git_clone(repo_url: str, args: tuple):
    """Safely executes git clone on the host with option injection protection."""
    if not validate_repo_url(repo_url):
        raise ValueError(f"Invalid repository URL: {repo_url}")
    # Use -- to separate options from the positional repo_url argument
    git_cmd = ["git", "clone", "--"] + [repo_url] + list(args)
    subprocess.run(git_cmd, check=True)

def get_alias_script(current_exe: str) -> str:
    """Returns the PowerShell alias script block for RepoShield."""
    return f"""
# RepoShield Global Command
function reposhield {{
    {current_exe} $args
}}

# RepoShield Git Interceptor
function git {{
    if ($args[0] -eq 'clone') {{
        {current_exe} clone $args[1..($args.Length-1)]
    }} else {{
        git.exe $args
    }}
}}
"""

def install_powershell_interceptor(current_exe: str, profile_path: Path):
    """Installs the PowerShell alias scripts, removing any old version first."""
    # Remove old blocks before appending to prevent duplicates
    if profile_path.exists():
        content = profile_path.read_text(encoding="utf-8")
        content = strip_reposhield_blocks(content)
        profile_path.write_text(content, encoding="utf-8")

    alias_script = get_alias_script(current_exe)
    with open(profile_path, "a", encoding="utf-8") as f:
        f.write("\n" + alias_script)

def strip_reposhield_blocks(content: str) -> str:
    """
    Removes RepoShield function blocks from PowerShell profile content.
    Uses line-by-line parsing instead of regex to avoid ReDoS risks.
    """
    lines = content.splitlines(keepends=True)
    result = []
    skip_depth = 0
    in_reposhield_block = False

    for line in lines:
        stripped = line.strip()

        # Detect start of a RepoShield block
        if stripped.startswith("# RepoShield"):
            in_reposhield_block = True
            continue

        if in_reposhield_block:
            # Track brace depth to know when the function ends
            skip_depth += stripped.count("{") - stripped.count("}")
            if skip_depth <= 0 and "{" not in stripped and "}" not in stripped and stripped == "":
                # Blank line after block end — stop skipping
                in_reposhield_block = False
                skip_depth = 0
            elif skip_depth <= 0 and "}" in stripped:
                # The closing brace of the function
                in_reposhield_block = False
                skip_depth = 0
            continue

        result.append(line)

    return "".join(result)