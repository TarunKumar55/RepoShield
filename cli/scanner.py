import uuid
import time
import threading
import docker
import json
from rich.console import Console

console = Console()
IMAGE_NAME = "reposhield/scanner:latest"

# Maximum time (seconds) for each container to run before being killed
CONTAINER_TIMEOUT_SECONDS = 600

def build_or_pull_image(client):
    try:
        client.images.get(IMAGE_NAME)
    except docker.errors.ImageNotFound:
        console.print("[yellow]Scanner image not found locally. Building from Dockerfile...[/yellow]")
        import os
        import sys
        
        # Determine base path for Dockerfile.scanner
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # Running as compiled PyInstaller executable
            base_path = os.path.join(sys._MEIPASS, 'cli')
        else:
            # Running as normal Python script
            base_path = os.path.dirname(os.path.abspath(__file__))

        dockerfile_name = "Dockerfile.scanner"
        
        try:
            client.images.build(
                path=base_path, 
                dockerfile=dockerfile_name, 
                tag=IMAGE_NAME, 
                rm=True
            )
            console.print("[green]Scanner image built successfully.[/green]")
        except Exception as e:
            console.print(f"[bold red]Failed to build Docker image: {e}[/bold red]")
            raise e


def _run_container_with_timeout(client, timeout_seconds, **kwargs):
    """
    Runs a Docker container with an external timeout watchdog.
    Returns the container logs on success.
    Raises TimeoutError if the container exceeds the timeout.
    """
    container = client.containers.run(detach=True, **kwargs)
    
    try:
        result = container.wait(timeout=timeout_seconds)
        logs = container.logs(stdout=True, stderr=False)
        exit_code = result.get("StatusCode", -1)
        
        if exit_code != 0:
            stderr_logs = container.logs(stdout=False, stderr=True)
            err_msg = stderr_logs.decode("utf-8").strip() if stderr_logs else f"Exit code {exit_code}"
            raise docker.errors.ContainerError(
                container, exit_code, kwargs.get("command", ""), IMAGE_NAME, err_msg
            )
        
        return logs
    except Exception as e:
        # If it's a timeout from the wait(), kill the container
        try:
            container.kill()
        except Exception:
            pass
        raise
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass


def run_scan(repo_url: str) -> dict:
    """
    Orchestrates the two-container handoff for maximum security.
    Container A: Network enabled, clones repo to volume.
    Container B: Network disabled, read-only root, scans volume.
    """
    client = docker.from_env()
    build_or_pull_image(client)
    
    vol_name = f"reposhield_scan_{uuid.uuid4().hex}"
    
    try:
        # Create a volume to pass data between the two isolated containers
        volume = client.volumes.create(name=vol_name)
        
        # ---------------------------------------------------------
        # Container A: The Cloner (Needs Network)
        # Runs as non-root; Dockerfile ensures /scan_repo is writable
        # ---------------------------------------------------------
        try:
            _run_container_with_timeout(
                client,
                timeout_seconds=CONTAINER_TIMEOUT_SECONDS,
                image=IMAGE_NAME,
                command=["clone", repo_url],
                network_disabled=False,
                volumes={vol_name: {'bind': '/scan_repo', 'mode': 'rw'}}
            )
        except docker.errors.ContainerError as e:
            err_msg = e.stderr.decode("utf-8").strip() if isinstance(e.stderr, bytes) else str(e.stderr or e)
            return {"error": f"Failed to clone repository during isolation phase: {err_msg}"}
        except TimeoutError:
            return {"error": "Clone container timed out. The repository may be too large or unresponsive."}

        # ---------------------------------------------------------
        # Container B: The Scanner (Zero Network, Read-Only, Unprivileged)
        # ---------------------------------------------------------
        try:
            logs = _run_container_with_timeout(
                client,
                timeout_seconds=CONTAINER_TIMEOUT_SECONDS,
                image=IMAGE_NAME,
                command=["scan"],
                stdout=True,
                stderr=False,
                mem_limit="512m",
                nano_cpus=500000000,
                network_disabled=True,
                read_only=True,
                tmpfs={"/tmp": "", "/home/scanner_user": ""},
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                volumes={vol_name: {'bind': '/scan_repo', 'mode': 'ro'}}
            )
            # Parse the output
            output_str = logs.decode("utf-8").strip()
            
            try:
                return json.loads(output_str)
            except json.JSONDecodeError:
                console.print("[bold red]Failed to parse scanner output. Raw output:[/bold red]")
                console.print(output_str)
                return {"error": "Invalid JSON output from scanner"}
                
        except docker.errors.ContainerError as e:
            err_msg = e.stderr.decode('utf-8') if isinstance(e.stderr, bytes) else str(e.stderr or e)
            console.print(f"[bold red]Scanner container failed to execute:[/bold red]\n{err_msg}")
            return {"error": "Scanner container execution failed"}
        except TimeoutError:
            return {"error": "Scanner container timed out. The repository may be too large for analysis."}
            
    except Exception as e:
        return {"error": f"Unexpected error during scan orchestration: {str(e)}"}
        
    finally:
        # Always clean up the volume with retry logic to handle race conditions
        for attempt in range(3):
            try:
                vol = client.volumes.get(vol_name)
                vol.remove(force=True)
                break
            except docker.errors.NotFound:
                break
            except Exception as e:
                if attempt < 2:
                    time.sleep(1)  # Brief delay before retry
                else:
                    console.print(f"[yellow]Warning: Failed to cleanup volume {vol_name}: {e}[/yellow]")

def parse_findings(raw: dict, repo_url: str = ""):
    """
    Normalizes raw scanner output into a unified ScanResult with Finding objects.
    Applies config-based filtering (ignored severities/categories).
    """
    from models import Finding, ScanResult
    from config import load_config

    result = ScanResult(repo_url=repo_url)

    if "error" in raw:
        result.errors.append(raw["error"])
        result.verdict = "FAIL"
        return result

    all_findings = []

    # Scan errors
    for err in raw.get("scan_errors", []):
        all_findings.append(Finding(
            tool="scanner", type="error", category="Scanner Error",
            severity="HIGH", title=err,
        ))

    # Gitleaks (secrets)
    for r in raw.get("secrets", []):
        all_findings.append(Finding(
            tool="gitleaks", type="secret", category="Secret",
            severity="CRITICAL",
            file=r.get("File", ""),
            line=r.get("StartLine"),
            title=r.get("Description", "Hardcoded Secret"),
            detail=r.get("Match", ""),
        ))

    # Semgrep (SAST)
    for r in raw.get("sast", []):
        severity = r.get("extra", {}).get("severity", "UNKNOWN")
        if severity in ("ERROR", "WARNING"):
            display_severity = "HIGH" if severity == "ERROR" else "MEDIUM"
            all_findings.append(Finding(
                tool="semgrep", type="sast", category="SAST",
                severity=display_severity,
                file=r.get("path", ""),
                line=r.get("start", {}).get("line"),
                title=r.get("check_id", "Vulnerability Detected"),
                detail=r.get("extra", {}).get("message", ""),
            ))

    # Bandit (Python SAST)
    for r in raw.get("bandit", []):
        severity = r.get("issue_severity", "UNKNOWN")
        if severity in ("HIGH", "MEDIUM"):
            cwe_raw = r.get("issue_cwe")
            cwe_id = str(cwe_raw.get("id", "")) if isinstance(cwe_raw, dict) else None
            all_findings.append(Finding(
                tool="bandit", type="sast", category="Python SAST",
                severity=severity,
                file=r.get("filename", ""),
                line=r.get("line_number"),
                title=r.get("test_name", "Security Issue"),
                detail=r.get("issue_text", ""),
                cwe=cwe_id,
            ))

    # Hook scanner (install hooks & CI/CD poisoning)
    for r in raw.get("hooks", []):
        all_findings.append(Finding(
            tool="hook-scanner", type="hook", category="Install Hook",
            severity=r.get("severity", "HIGH"),
            file=r.get("file", ""),
            line=r.get("line"),
            title=r.get("description", "Suspicious install hook"),
            detail=r.get("match", ""),
        ))

    # Anomaly scanner (binaries, oversized files, sensitive filenames, polyglots)
    for r in raw.get("anomalies", []):
        all_findings.append(Finding(
            tool="anomaly-scanner", type="anomaly", category="File Anomaly",
            severity=r.get("severity", "MEDIUM"),
            file=r.get("file", ""),
            line=r.get("line"),
            title=r.get("description", "Suspicious file detected"),
            detail=r.get("match", ""),
        ))

    # Apply config-based filtering (backward-compatible with existing configs)
    config = load_config()
    ignored_severities = [s.upper() for s in config.get("ignored_severities", [])]
    ignored_categories = config.get("ignored_categories", [])

    for finding in all_findings:
        if finding.severity in ignored_severities:
            continue
        if finding.category in ignored_categories:
            continue
        result.findings.append(finding)

    result.verdict = "FAIL" if result.findings else "PASS"
    result.raw_findings = raw
    return result