import typer
import subprocess
import sys
import os
import re
import json
import webbrowser
import shutil
from pathlib import Path

# Fix Windows console emoji printing issues
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8' and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.color import Color

app = typer.Typer(help="RepoShield: Zero-Trust Git Clone CLI")
console = Console()

# Strict URL pattern — defense-in-depth (duplicated from services.py)
URL_PATTERN = re.compile(
    r'^(https://[a-zA-Z0-9._\-]+(/[a-zA-Z0-9._\-]+)*(/[a-zA-Z0-9._\-]+\.git)?/?'
    r'|git@[a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-/]+\.git)$'
)

def get_gradient_banner():
    banner_lines = [
        r"    ____  __________  ____         _____ __  __ _________  __     ____  ",
        r"   / __ \/ ____/ __ \/ __ \       / ___// / / //  _/ ____// /    / __ \ ",
        r"  / /_/ / __/ / /_/ / / / / ____  \__ \/ /_/ / / // __/  / /    / / / / ",
        r" / _, _/ /___/ ____/ /_/ /  ___  ___/ / __  /_/ // /___ / /___ / /_/ /  ",
        r"/_/ |_/_____/_/    \____/        ____/_/ /_//___/_____//_____//_____/   "
    ]
    
    text = Text()
    # Gradient from Cyan (#00FFFF) to Pink/Purple (#FF00FF)
    start_r, start_g, start_b = 0, 255, 255
    end_r, end_g, end_b = 255, 0, 255
    
    max_len = max(len(line) for line in banner_lines)
    
    for i, line in enumerate(banner_lines):
        for j, char in enumerate(line):
            ratio = j / max_len if max_len > 0 else 0
            r = int(start_r + (end_r - start_r) * ratio)
            g = int(start_g + (end_g - start_g) * ratio)
            b = int(start_b + (end_b - start_b) * ratio)
            
            text.append(char, style=f"bold rgb({r},{g},{b})")
        if i < len(banner_lines) - 1:
            text.append("\n")
            
    return text

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        console.print(get_gradient_banner())
        console.print(ctx.get_help())
    else:
        console.print(get_gradient_banner())

def check_docker():
    """Check if Docker is installed and running."""
    try:
        # Run docker --version to check if it's installed
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        # Check if daemon is running
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def prompt_docker_installation():
    """Prompt the user to install Docker."""
    msg = """
[bold red]🛑 Docker Required[/bold red]

RepoShield requires Docker to safely isolate and scan code before it touches your machine. 
[blue][link=https://www.docker.com/products/docker-desktop/]Click Here to Download Docker Desktop[/link][/blue]

*(Press Enter once Docker is installed and running...)*
    """
    console.print(Panel(msg, title="Dependencies Missing", border_style="red"))
    input()
    # Check again after they press Enter
    if not check_docker():
        console.print("[bold red]Docker is still not running. Exiting...[/bold red]")
        raise typer.Exit(code=1)
    console.print("[bold green]✅ Docker detected![/bold green]")

@app.command(context_settings={"ignore_unknown_options": True})
def clone(
    ctx: typer.Context,
    repo_url: str,
    output: str = typer.Option("table", help="Output format: 'table' (default) or 'json'"),
    auto: bool = typer.Option(False, help="Non-interactive mode. Uses policy engine verdict without prompts."),
):
    """
    Clone a repository through RepoShield's security sandbox.
    
    Exit codes: 0 = clean (PASS), 1 = blocked (FAIL), 2 = scanner error, 3 = invalid input
    """
    from services import is_docker_running, execute_scan, generate_report, execute_git_clone, validate_repo_url
    from logger import ScanLogger
    
    scan_log = ScanLogger()
    json_mode = output.lower() == "json"
    
    # HOST-SIDE URL validation (defense-in-depth, duplicates container check)
    if not validate_repo_url(repo_url):
        scan_log.log_error("Invalid repository URL", context=repo_url)
        if json_mode:
            print(json.dumps({"error": "Invalid repository URL", "exit_code": 3}))
        else:
            console.print("[bold red]❌ Invalid repository URL. Only https:// and git@ protocols with valid characters are allowed.[/bold red]")
        raise typer.Exit(code=3)
    
    if not is_docker_running():
        if auto:
            if json_mode:
                print(json.dumps({"error": "Docker is not running", "exit_code": 2}))
            else:
                console.print("[bold red]❌ Docker is not running. Cannot scan in auto mode.[/bold red]")
            raise typer.Exit(code=2)
        prompt_docker_installation()
    
    scan_log.log_scan_start(repo_url, auto_mode=auto, output_format=output)
    
    if not json_mode:
        console.print(f"[bold cyan]◇[/bold cyan] 🛡️  [bold blue]Initializing Secure Sandbox for:[/bold blue] {repo_url}")
        console.print("[bold cyan]│[/bold cyan] ⏳ Pulling isolated scanner container and analyzing...")
    
    try:
        result = execute_scan(repo_url)
    except Exception as e:
        if json_mode:
            print(json.dumps({"error": str(e), "exit_code": 2}))
        else:
            console.print(f"[bold red]❌ Failed to execute scan: {e}[/bold red]")
        scan_log.log_error(str(e), context="execute_scan")
        raise typer.Exit(code=2)

    # Log scan completion for all output modes
    scan_log.log_scan_complete(result)

    # ── JSON output mode ────────────────────────────────────────
    if json_mode:
        scan_log.log_verdict(result.verdict, "json_output")
        print(json.dumps(result.model_dump(), indent=2, default=str))
        exit_code = 0 if result.verdict == "PASS" else 1
        raise typer.Exit(code=exit_code)

    # ── Handle scan errors (Docker failures, timeouts, etc.) ───
    if result.errors and not result.findings:
        console.print(f"[bold cyan]◇[/bold cyan] [bold red]❌ Scan Error:[/bold red] {result.summary}")
        raise typer.Exit(code=2)

    # ── PASS verdict ────────────────────────────────────────────
    if result.verdict == "PASS":
        console.print(f"[bold cyan]◇[/bold cyan] ✅ [bold green]Codebase is clean. Cloning to host...[/bold green] [dim]({result.scan_duration_seconds}s)[/dim]")
        scan_log.log_verdict("PASS", "clone")
        try:
            execute_git_clone(repo_url, ctx.args)
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red]❌ Clone failed: {e}[/bold red]")
        return

    # ── WARN or FAIL — show risk score and findings ─────────────
    score_color = "red" if result.risk_score >= 7 else "yellow" if result.risk_score >= 4 else "green"
    console.print(f"[bold cyan]◇[/bold cyan] [bold red]⚠️  Issues Found![/bold red] {result.summary}")
    console.print(f"[bold cyan]│[/bold cyan] Risk Score: [{score_color}]{result.risk_score}/10.0[/{score_color}]  Verdict: [bold {'red' if result.verdict == 'FAIL' else 'yellow'}]{result.verdict}[/bold {'red' if result.verdict == 'FAIL' else 'yellow'}]")
    
    if result.findings and not auto:
        if Confirm.ask("[bold cyan]◇[/bold cyan] Do you want to see the details?", default=False):
            table = Table(show_header=True, header_style="bold magenta", border_style="cyan")
            table.add_column("Severity", style="red", width=12)
            table.add_column("Category", style="yellow", width=15)
            table.add_column("Description", style="white")
            
            # Show up to 15 issues so we don't flood the terminal
            for finding in result.findings[:15]:
                sev = finding.severity
                severity_colored = f"[bold red]{sev}[/bold red]" if sev == "CRITICAL" else f"[red]{sev}[/red]"
                desc = finding.title
                if finding.file:
                    desc += f" [dim]({finding.file}:{finding.line or '?'})[/dim]"
                table.add_row(severity_colored, finding.category, desc)
            
            console.print(table)
            if len(result.findings) > 15:
                console.print(f"[bold cyan]│[/bold cyan] [bold yellow]...and {len(result.findings) - 15} more issues hidden.[/bold yellow]")
        
        if Confirm.ask("[bold cyan]◇[/bold cyan] Do you want to generate a detailed report?", default=False):
            try:
                # Write JSON report to safe directory
                reports_dir = Path(os.path.expanduser("~")) / ".reposhield" / "reports"
                reports_dir.mkdir(parents=True, exist_ok=True)
                json_path = reports_dir / "reposhield_report.json"
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(result.model_dump(), f, indent=2, default=str)
                    
                report_path = generate_report(result)
                console.print(f"[bold green]✅ Here is your generated report: {report_path}[/bold green]")
                
                console.print("[bold cyan]│[/bold cyan] Opening report in your default web browser...")
                webbrowser.open(Path(report_path).as_uri())
            except Exception as e:
                console.print(f"[bold red]❌ Failed to generate report: {e}[/bold red]")

    # ── FAIL verdict = automatic block ──────────────────────────
    if result.verdict == "FAIL":
        from config import load_config
        config = load_config()
        console.print(f"[bold cyan]│[/bold cyan] [bold red]BLOCKED: Risk score {result.risk_score}/10.0 exceeds threshold {config.get('risk_threshold', 5.0)}.[/bold red]")
        console.print("[bold cyan]│[/bold cyan] 🚫 Clone aborted. Your machine remains safe.")
        scan_log.log_verdict("FAIL", "blocked")
        raise typer.Exit(code=1)

    # ── WARN verdict ────────────────────────────────────────────
    if auto:
        # Auto mode: WARN = allow clone (only FAIL blocks)
        console.print(f"[bold cyan]◇[/bold cyan] [bold yellow]AUTO MODE:[/bold yellow] Verdict is WARN — proceeding with clone.")
        try:
            execute_git_clone(repo_url, ctx.args)
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red]❌ Clone failed: {e}[/bold red]")
    elif Confirm.ask("[bold cyan]◇[/bold cyan] Are you sure you want to clone this to your host?", default=False):
        try:
            execute_git_clone(repo_url, ctx.args)
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red]❌ Clone failed: {e}[/bold red]")
    else:
        scan_log.log_verdict("WARN", "user_aborted")
        console.print("[bold cyan]│[/bold cyan] 🚫 Clone aborted. Your machine remains safe.")

@app.command()
def install():
    from services import install_powershell_interceptor, get_alias_script
    
    console.print("[bold cyan]◇[/bold cyan] [bold yellow]This will configure PowerShell to intercept `git clone` commands.[/bold yellow]")
    if not Confirm.ask("[bold cyan]◇[/bold cyan] Do you want to proceed?"):
        console.print("[bold cyan]│[/bold cyan] Installation aborted.")
        return

    # Reliably get PowerShell profile path without subprocess encoding issues
    documents_dir = os.path.join(os.environ.get('USERPROFILE', os.path.expanduser('~')), 'Documents')
    ps_profile = os.path.join(documents_dir, 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1')

    profile_path = Path(ps_profile)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Get the path to the current executable or script
    if getattr(sys, 'frozen', False):
        current_exe = f'& "{sys.executable}"'
    else:
        current_exe = f'python "{os.path.abspath(__file__)}"'

    # Check if already installed (full current version)
    if profile_path.exists():
        content = profile_path.read_text(encoding="utf-8")
        if "RepoShield Global Command" in content and "RepoShield Git Interceptor" in content:
            console.print("[bold green]RepoShield is already fully installed and up to date![/bold green]")
            return
        
        if "RepoShield" in content:
            console.print("[bold yellow]Found old version of RepoShield. Updating to latest...[/bold yellow]")
            # install_powershell_interceptor handles stripping old blocks before appending

    # Delegate to services.py — single source of truth for the alias script
    install_powershell_interceptor(current_exe, profile_path)
        
    console.print(f"[bold green]✅ Interceptor installed to {profile_path}[/bold green]")
    console.print("Please restart your terminal for the changes to take effect.")

@app.command()
def configure():
    from config import load_config, save_config
    from rich.prompt import Prompt
    
    config = load_config()
    console.print("[bold cyan]◇[/bold cyan] 🛡️  [bold blue]RepoShield Security Policy Configuration[/bold blue]")
    
    # Configure Ignored Severities
    current_sev = ", ".join(config.get("ignored_severities", [])) or "None"
    console.print(f"[bold cyan]│[/bold cyan] Current ignored severities: [yellow]{current_sev}[/yellow]")
    if Confirm.ask("[bold cyan]◇[/bold cyan] Do you want to ignore specific severities (e.g. MEDIUM)?", default=False):
        sevs = Prompt.ask("[bold cyan]│[/bold cyan] Enter severities to ignore (comma-separated, or leave blank)")
        if sevs.strip():
            config["ignored_severities"] = [s.strip().upper() for s in sevs.split(",")]
        else:
            config["ignored_severities"] = []
            
    # Configure Ignored Categories
    current_cat = ", ".join(config.get("ignored_categories", [])) or "None"
    console.print(f"[bold cyan]│[/bold cyan] Current ignored categories: [yellow]{current_cat}[/yellow]")
    if Confirm.ask("[bold cyan]◇[/bold cyan] Do you want to ignore specific categories (e.g. Python SAST)?", default=False):
        cats = Prompt.ask("[bold cyan]│[/bold cyan] Enter categories to ignore (comma-separated, or leave blank)")
        if cats.strip():
            config["ignored_categories"] = [c.strip() for c in cats.split(",")]
        else:
            config["ignored_categories"] = []
            
    # Configure Strict Mode
    current_strict = config.get("strict_mode", False)
    console.print(f"[bold cyan]│[/bold cyan] Current Strict Mode: [yellow]{'Enabled' if current_strict else 'Disabled'}[/yellow]")
    if Confirm.ask("[bold cyan]◇[/bold cyan] Do you want to enable Strict Mode (automatically blocks clones without asking)?", default=current_strict):
        config["strict_mode"] = True
    else:
        config["strict_mode"] = False
        
    save_config(config)
    console.print("[bold green]✅ Security policies updated successfully![/bold green]")

@app.command()
def uninstall():
    """
    Removes RepoShield's integration from PowerShell and deletes configuration files.
    """
    from services import strip_reposhield_blocks
    
    console.print("[bold cyan]◇[/bold cyan] [bold red]This will remove RepoShield's integration from your system.[/bold red]")
    if not Confirm.ask("[bold cyan]◇[/bold cyan] Are you sure you want to proceed?"):
        return

    # 1. Remove from PowerShell profile
    documents_dir = os.path.join(os.environ.get('USERPROFILE', os.path.expanduser('~')), 'Documents')
    ps_profile = os.path.join(documents_dir, 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1')
    profile_path = Path(ps_profile)

    if profile_path.exists():
        content = profile_path.read_text(encoding="utf-8")
        if "# RepoShield" in content:
            console.print("[bold cyan]│[/bold cyan] Removing PowerShell interceptors...")
            
            # Use safe line-by-line parser instead of regex (prevents ReDoS)
            new_content = strip_reposhield_blocks(content)
            
            profile_path.write_text(new_content.strip() + "\n", encoding="utf-8")
            console.print("[bold green]✅ PowerShell profile cleaned.[/bold green]")
        else:
            console.print("[bold yellow]│[/bold yellow] No RepoShield integration found in PowerShell profile.")
    else:
        console.print("[bold yellow]│[/bold yellow] PowerShell profile not found. Skipping profile cleanup.")

    # 2. Delete config directory
    home = Path(os.path.expanduser("~"))
    reposhield_dir = home / ".reposhield"
    if reposhield_dir.exists():
        try:
            shutil.rmtree(reposhield_dir)
            console.print("[bold green]✅ Configuration directory (~/.reposhield) removed.[/bold green]")
        except Exception as e:
            console.print(f"[bold red]❌ Failed to remove config directory: {e}[/bold red]")

    # 3. Docker cleanup
    if Confirm.ask("[bold cyan]◇[/bold cyan] Do you want to remove the Docker scanner image to free up space?", default=True):
        try:
            import docker
            client = docker.from_env()
            from scanner import IMAGE_NAME
            console.print(f"[bold cyan]│[/bold cyan] Removing Docker image {IMAGE_NAME}...")
            client.images.remove(IMAGE_NAME, force=True)
            console.print(f"[bold green]✅ Docker image removed.[/bold green]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not remove Docker image: {e}[/yellow]")

    console.print("\n[bold green]✨ RepoShield has been successfully uninstalled![/bold green]")
    console.print("[bold yellow]Note:[/bold yellow] You can now safely delete the executable and this source folder.")

if __name__ == "__main__":
    app()