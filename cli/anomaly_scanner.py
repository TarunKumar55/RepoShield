"""
File Anomaly & Binary Detector for RepoShield.
Detects suspicious files that don't belong in a source code repository:
- Executable binaries (.exe, .dll, .so) committed to source
- Oversized individual files (possible zip bombs)
- Long base64 strings (embedded payloads)
- Suspicious committed filenames (.env, private keys, certs)
- Polyglot files (magic bytes mismatch with extension)

Runs inside the air-gapped scanner container — no external dependencies.
Usage: python anomaly_scanner.py <repo_dir> <output_json>
"""
import os
import re
import sys
import json
import struct


# ── Configuration ─────────────────────────────────────────────────────────────

MAX_FILE_SIZE_MB = 10          # Files larger than this are flagged
MAX_REPO_SIZE_MB = 500         # Total repo size limit (reported, not enforced here)
BASE64_MIN_LENGTH = 500        # Minimum length to flag a base64 string
BASE64_CHUNK_THRESHOLD = 3     # Minimum number of long b64 chunks per file to flag

# Binary extensions that should never appear in a source repo
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".com", ".bat", ".cmd",   # Windows
    ".so", ".dylib", ".o", ".a",                       # Linux/macOS native
    ".bin", ".elf",                                    # Generic binaries
    ".pyc", ".pyo", ".pyd",                           # Python bytecode
    ".class", ".jar",                                  # Java
    ".apk", ".ipa", ".dex",                           # Mobile
}

# Filenames that strongly suggest sensitive data committed by mistake
SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".htpasswd", "credentials", "secrets.yml", "secrets.yaml",
    ".npmrc", ".pypirc", "terraform.tfvars",
}

SENSITIVE_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
    ".cer", ".crt", ".der",
}

# Magic byte signatures: (bytes_to_check, offset, description)
MAGIC_SIGNATURES = [
    (b"MZ", 0, "Windows PE executable"),
    (b"\x7fELF", 0, "ELF binary (Linux/macOS executable)"),
    (b"PK\x03\x04", 0, "ZIP archive"),
    (b"\xca\xfe\xba\xbe", 0, "Java class file or macOS fat binary"),
    (b"\xfe\xed\xfa\xce", 0, "macOS Mach-O executable (32-bit)"),
    (b"\xfe\xed\xfa\xcf", 0, "macOS Mach-O executable (64-bit)"),
    (b"\xcf\xfa\xed\xfe", 0, "macOS Mach-O executable (reversed)"),
    (b"#!/", 0, "Shell script with shebang"),
]

# Source extensions that should NOT be binaries
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".rb", ".swift",
    ".kt", ".scala", ".r", ".sh", ".bash", ".zsh", ".ps1",
    ".yml", ".yaml", ".json", ".xml", ".toml", ".ini", ".cfg",
    ".md", ".txt", ".html", ".css", ".sql",
}

BASE64_PATTERN = re.compile(
    r'[A-Za-z0-9+/]{' + str(BASE64_MIN_LENGTH) + r',}={0,2}'
)


def get_magic_bytes(filepath: str) -> bytes:
    try:
        with open(filepath, "rb") as f:
            return f.read(8)
    except Exception:
        return b""


def check_polyglot(filepath: str, ext: str) -> str | None:
    """
    Detect if a file's magic bytes don't match its extension.
    Returns a description string if suspicious, None if clean.
    """
    if ext not in SOURCE_EXTENSIONS:
        return None

    magic = get_magic_bytes(filepath)
    for signature, offset, description in MAGIC_SIGNATURES:
        if magic[offset:offset + len(signature)] == signature:
            # Shell scripts with .py/.js extensions are OK to skip
            if signature == b"#!/" and ext in (".sh", ".bash", ".zsh"):
                continue
            return f"Source file ({ext}) contains {description} magic bytes"
    return None


def scan_for_anomalies(repo_dir: str) -> list[dict]:
    findings = []
    total_size = 0

    for root, dirs, files in os.walk(repo_dir):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in {
            ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"
        }]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, repo_dir).replace("\\", "/")
            ext = os.path.splitext(filename)[1].lower()
            base = os.path.basename(filename).lower()

            try:
                file_size = os.path.getsize(filepath)
            except OSError:
                continue

            total_size += file_size

            # 1. Committed binary executables
            if ext in BINARY_EXTENSIONS:
                findings.append({
                    "file": rel_path,
                    "line": None,
                    "severity": "HIGH",
                    "description": f"Binary executable committed to repository ({ext})",
                    "match": f"{file_size // 1024}KB {ext} file",
                })
                continue  # Don't run other checks on known binaries

            # 2. Oversized files
            file_size_mb = file_size / (1024 * 1024)
            if file_size_mb > MAX_FILE_SIZE_MB:
                findings.append({
                    "file": rel_path,
                    "line": None,
                    "severity": "MEDIUM",
                    "description": f"Oversized file ({file_size_mb:.1f}MB) — possible zip bomb or data exfiltration payload",
                    "match": f"{file_size_mb:.1f}MB",
                })

            # 3. Sensitive filenames
            if base in SENSITIVE_FILENAMES or ext in SENSITIVE_EXTENSIONS:
                findings.append({
                    "file": rel_path,
                    "line": None,
                    "severity": "CRITICAL",
                    "description": f"Sensitive credential file committed to repository",
                    "match": filename,
                })
                continue

            # 4. Polyglot detection (source files with binary magic bytes)
            polyglot = check_polyglot(filepath, ext)
            if polyglot:
                findings.append({
                    "file": rel_path,
                    "line": None,
                    "severity": "HIGH",
                    "description": polyglot,
                    "match": f"Magic: {get_magic_bytes(filepath)[:4].hex()}",
                })
                continue

            # 5. Base64 obfuscation in source files (skip very large files)
            if ext in SOURCE_EXTENSIONS and file_size < 1 * 1024 * 1024:
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    matches = BASE64_PATTERN.findall(content)
                    if len(matches) >= BASE64_CHUNK_THRESHOLD:
                        findings.append({
                            "file": rel_path,
                            "line": None,
                            "severity": "MEDIUM",
                            "description": f"Possible embedded payload — {len(matches)} long base64 strings detected",
                            "match": matches[0][:80] + "...",
                        })
                except Exception:
                    pass

    # 6. Total repo size check
    total_mb = total_size / (1024 * 1024)
    if total_mb > MAX_REPO_SIZE_MB:
        findings.append({
            "file": ".",
            "line": None,
            "severity": "HIGH",
            "description": f"Repository total size ({total_mb:.0f}MB) exceeds {MAX_REPO_SIZE_MB}MB limit",
            "match": f"{total_mb:.0f}MB",
        })

    return findings


def main():
    if len(sys.argv) < 3:
        print("Usage: python anomaly_scanner.py <repo_dir> <output_json>", file=sys.stderr)
        sys.exit(1)

    repo_dir = sys.argv[1]
    output_file = sys.argv[2]

    findings = scan_for_anomalies(repo_dir)

    with open(output_file, "w") as f:
        json.dump(findings, f)


if __name__ == "__main__":
    main()
