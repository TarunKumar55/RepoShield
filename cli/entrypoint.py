import sys
import subprocess
import json
import os
import re
import concurrent.futures

# Strict URL pattern: only https:// or git@ protocols with valid characters
URL_PATTERN = re.compile(
    r'^(https://[a-zA-Z0-9._\-]+(/[a-zA-Z0-9._\-]+)*(/[a-zA-Z0-9._\-]+\.git)?/?'
    r'|git@[a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-/]+\.git)$'
)

# Max total size of cloned repo (500MB) to prevent zip-bomb style attacks
MAX_REPO_SIZE_BYTES = 500 * 1024 * 1024


def get_dir_size(path):
    """Recursively calculate directory size in bytes."""
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def run_scanner(name, cmd, cwd, output_file):
    env = os.environ.copy()
    env["HOME"] = "/tmp"  # Use writable tmpfs for caches/configs
    # Prevent Semgrep from phoning home inside the air-gapped scanner container
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    env["SEMGREP_SEND_METRICS"] = "off"
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300,
            env=env
        )
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                return name, json.load(f), None
        # Exit code 0 or 1 with no output file = clean scan, no findings
        # (e.g. gitleaks exits 0 and writes no file when no secrets found)
        # Exit code >= 2 = real scanner failure
        if result.returncode <= 1:
            return name, None, None
        return name, None, f"{name} failed (exit code {result.returncode}). Stderr: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return name, None, f"{name} scan timed out after 300 seconds."
    except Exception as e:
        return name, None, f"{name} scan encountered an error: {str(e)}"


def clone_mode(repo_url):
    # Strict Validation with regex
    if not URL_PATTERN.match(repo_url):
        print("Invalid repository URL format. Only https:// and git@ URLs with valid characters are allowed.", file=sys.stderr)
        sys.exit(1)

    clone_dir = "/scan_repo/repo"

    try:
        clone_result = subprocess.run(
            # Use -- to prevent option injection via repo_url
            ["git", "clone", "--depth", "1", "--", repo_url, clone_dir],
            capture_output=True,
            text=True,
            timeout=300
        )
        if clone_result.returncode != 0:
            print(f"Failed to clone repository: {clone_result.stderr.strip()}", file=sys.stderr)
            sys.exit(1)

        # Post-clone size check to prevent zip-bomb attacks
        repo_size = get_dir_size(clone_dir)
        if repo_size > MAX_REPO_SIZE_BYTES:
            print(f"Repository size ({repo_size} bytes) exceeds limit ({MAX_REPO_SIZE_BYTES} bytes). Aborting.", file=sys.stderr)
            sys.exit(1)

        print("Clone successful")
    except subprocess.TimeoutExpired:
        print("Git clone timed out after 300 seconds.", file=sys.stderr)
        sys.exit(1)


def scan_mode():
    clone_dir = "/scan_repo/repo"
    
    if not os.path.exists(clone_dir):
        print(json.dumps({"error": "Repository not found in volume. Clone step must have failed."}))
        sys.exit(1)

    findings = {
        "secrets": [],
        "sast": [],
        "bandit": [],
        "hooks": [],
        "anomalies": [],
        "scan_errors": []
    }

    scanners = [
        ("secrets", ["gitleaks", "detect", "--no-git", "--report-format", "json", "--report-path", "/tmp/gitleaks.json"], "/tmp/gitleaks.json"),
        ("sast", ["semgrep", "scan", "--config=/semgrep-rules/default.yml", "--json", "--metrics=off", "-o", "/tmp/semgrep.json"], "/tmp/semgrep.json"),
        ("bandit", ["bandit", "-r", ".", "-f", "json", "-o", "/tmp/bandit.json"], "/tmp/bandit.json"),
        ("hooks", ["python", "/hook_scanner.py", ".", "/tmp/hooks.json"], "/tmp/hooks.json"),
        ("anomalies", ["python", "/anomaly_scanner.py", ".", "/tmp/anomalies.json"], "/tmp/anomalies.json")
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(run_scanner, name, cmd, clone_dir, out_file): name 
            for name, cmd, out_file in scanners
        }
        
        for future in concurrent.futures.as_completed(futures):
            name, data, err = future.result()
            if err:
                findings["scan_errors"].append(err)
            elif data:
                if name == "secrets":
                    findings["secrets"] = data
                elif name == "sast":
                    findings["sast"] = data.get("results", [])
                elif name == "bandit":
                    findings["bandit"] = data.get("results", [])
                elif name == "hooks":
                    findings["hooks"] = data
                elif name == "anomalies":
                    findings["anomalies"] = data

    print(json.dumps(findings))


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No command provided. Use 'clone' or 'scan'."}))
        sys.exit(1)

    mode = sys.argv[1]
    
    if mode == "clone":
        if len(sys.argv) < 3:
            print("Missing repo_url for clone mode")
            sys.exit(1)
        clone_mode(sys.argv[2])
    elif mode == "scan":
        scan_mode()
    else:
        print(json.dumps({"error": f"Unknown mode: {mode}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()