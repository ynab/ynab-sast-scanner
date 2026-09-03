#!/usr/bin/env python3
"""
Runs a Socket Basics (SAST) scan locally against a target repository, mirroring the CI
workflow run against each repo on open pull requests.

Usage:
    scripts/dev/socket-basics.py [--output-dir <dir>] [--suppressions-ref <ref>] <path-to-repo>

Prerequisites:
    - a container runtime (Docker Desktop, colima, ...)
    - gh, authenticated — how the suppression configs are read
    - export SOCKET_SECURITY_API_KEY=<your-key>

This runs the same pinned Docker image CI runs, and that is the only mode. The image pins
opengrep and trufflehog to exactly the versions the CI job uses, so a local result predicts
the PR check.
"""

import csv
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# --- Args ---

usage = f"usage: {Path(sys.argv[0]).name} [--output-dir <dir>] [--suppressions-ref <ref>] <path-to-repo>"

_args = sys.argv[1:]
_output_dir_arg: str | None = None
_suppressions_ref: str | None = None

if "--suppressions-ref" in _args:
    idx = _args.index("--suppressions-ref")
    if idx + 1 >= len(_args):
        sys.exit(f"error: --suppressions-ref requires a ref argument\n{usage}")
    _suppressions_ref = _args.pop(idx + 1)
    _args.pop(idx)

if "--output-dir" in _args:
    idx = _args.index("--output-dir")
    if idx + 1 >= len(_args):
        sys.exit(f"error: --output-dir requires a path argument\n{usage}")
    _output_dir_arg = _args.pop(idx + 1)
    _args.pop(idx)

unknown = [a for a in _args if a.startswith("--")]
if unknown:
    sys.exit(f"error: unexpected argument '{unknown[0]}'\n{usage}")
if not _args:
    sys.exit(usage)
if len(_args) > 1:
    sys.exit(f"error: unexpected argument '{_args[1]}'\n{usage}")

target_repo = Path(_args[0]).resolve()
if not target_repo.is_dir():
    sys.exit(f"error: '{target_repo}' is not a directory")

# --- Paths ---

scanner_dir = Path(__file__).resolve().parent.parent.parent

SUPPRESSIONS_REPO = "ynab/ynab-sast-scanner-suppressions"


def clean_path(raw, workspace):
    """Reduce a scanner-reported path to something repo-relative."""
    workspace = workspace.rstrip("/")
    prefixes = (
        workspace + "/", workspace,
        workspace.lstrip("/") + "/", workspace.lstrip("/"),
        "/github/workspace/", "github/workspace/",
    )
    for prefix in prefixes:
        if raw.startswith(prefix):
            return raw[len(prefix):]
    return raw


# socket-basics logs its exact opengrep invocation at INFO, including every
# --exclude-rule it was told to skip — to avoid leaking suppressions in the 
# terminal, we redact it on the way out
_EXCLUDE_RULE_RUN = re.compile(r"(?:--exclude-rule \S+ ?)+")


def redact_suppressed_rules(line: str) -> str:
    return _EXCLUDE_RULE_RUN.sub("[suppressed rules redacted] ", line)


# --- Pre-flight ---

api_key = os.environ.get("SOCKET_SECURITY_API_KEY")
if not api_key:
    sys.exit("error: SOCKET_SECURITY_API_KEY is not set")

def warn_if_unshared(path: Path, what: str) -> None:
    """Flag the path if the container runtime does not share it into the VM.

    A warning rather than an error: colima mounts $HOME only unless configured otherwise, 
    while Docker Desktop also shares /Volumes, /private and /tmp by default. If the path 
    really isn't shared, the scan fails with a file-not-found from inside the container.
    """
    home = Path.home().resolve()
    try:
        path.resolve().relative_to(home)
    except ValueError:
        print(
            f"warning: {what} is outside your home directory:\n"
            f"         {path}\n"
            f"         colima shares only $HOME by default, so this may be invisible inside\n"
            f"         the container. Docker Desktop also shares /Volumes, /private and /tmp,\n"
            f"         so it is likely fine there. If the scan fails saying the config or\n"
            f"         workspace is missing, this is why.",
            file=sys.stderr,
        )


if not shutil.which("docker"):
    hint = "brew install docker"
    if list(Path("/opt/homebrew/Cellar/docker").glob("*")):
        hint = "brew link docker   # it is installed but not on your PATH"
    sys.exit(f"error: docker not found\n       {hint}")

if subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL).returncode != 0:
    starter = "colima start" if shutil.which("colima") else "open -a Docker"
    sys.exit(
        "error: the docker daemon is not reachable\n"
        f"       Start it with: {starter}"
    )

warn_if_unshared(target_repo, "the repo being scanned")


if not shutil.which("gh"):
    sys.exit(
        "error: the GitHub CLI (gh) is not installed\n"
        "       It is how suppression configs are read from the private "
        f"{SUPPRESSIONS_REPO} repo.\n"
        "       Install it: brew install gh && gh auth login"
    )

print(f"==> target repo:   {target_repo}")
# --- Resolve the pinned image ---

# Read the digest out of the CI workflow in this same repo rather than duplicating it here,
# so an upgrade touches one line and a local scan cannot drift from CI.
_workflow = scanner_dir / ".github/workflows/socket-basics.yml"
_match = re.search(r"SOCKET_BASICS_IMAGE:\s*(\S+)", _workflow.read_text())
if not _match:
    sys.exit(
        f"error: could not find SOCKET_BASICS_IMAGE in {_workflow}\n"
        f"       The pinned digest is read from the CI workflow so the two cannot disagree.\n"
        f"       If that variable was renamed, update this script."
    )
socket_basics_image = _match.group(1)
print(f"==> image:         {socket_basics_image}")


# --- Merge org and repo suppression configs ---

merge_script = scanner_dir / ".github/actions/merge-socket-config/merge_config.py"

# --- Fetch the suppression configs ---

def fetch_suppressions(dest_dir: Path) -> tuple[Path, Path]:
    """Return (org_config, repo_config). The repo config may not exist; that's normal."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    org_path = dest_dir / "org.json"
    repo_path = dest_dir / "repo.json"

    ref_qs = f"?ref={_suppressions_ref}" if _suppressions_ref else ""

    def gh_read(path: str) -> bytes | None:
        result = subprocess.run(
            ["gh", "api", f"repos/{SUPPRESSIONS_REPO}/contents/{path}{ref_qs}",
             "-H", "Accept: application/vnd.github.raw"],
            capture_output=True,
        )
        return result.stdout if result.returncode == 0 else None

    org = gh_read("org.json")
    if org is None:
        reachable = subprocess.run(
            ["gh", "api", f"repos/{SUPPRESSIONS_REPO}"],
            capture_output=True,
        ).returncode == 0
        if reachable:
            sys.exit(
                f"error: {SUPPRESSIONS_REPO} is readable but has no org.json at its root.\n"
                f"       The scan can't run without the org-level config. If the suppressions\n"
                f"       migration is still in flight, this repo isn't populated yet."
            )
        sys.exit(
            f"error: could not read {SUPPRESSIONS_REPO}\n"
            f"       It's private, so this needs your GitHub credentials:\n"
            f"         gh auth login\n"
            f"       If you're signed in and still see this, you may not have access —\n"
            f"       ask in #security."
        )
    org_path.write_bytes(org)

    repo_name = github_repository.split("/")[-1]
    repo = gh_read(f"suppressions/{repo_name}.json")
    if repo is None:
        print(f"==> suppressions:  org only (no suppressions/{repo_name}.json)")
        repo_path.unlink(missing_ok=True)
    else:
        print(f"==> suppressions:  org + {repo_name}")
        repo_path.write_bytes(repo)

    return org_path, repo_path

# --- Run the scan ---

commit_sha = subprocess.check_output(
    ["git", "-C", str(target_repo), "rev-parse", "HEAD"], text=True
).strip()

origin_url = subprocess.check_output(
    ["git", "-C", str(target_repo), "remote", "get-url", "origin"], text=True
).strip()
github_repository = re.sub(r".*github\.com[:/](.+?)(?:\.git)?$", r"\1", origin_url)

print(f"==> Scanning {target_repo} ({github_repository}) on commit {commit_sha[:12]}")

# Directory names to keep exclude from the Trufflehog secret scan. 
TRUFFLEHOG_EXCLUDE_DIRS = "node_modules,.yarn,dist,build,coverage,tmp,.cache,.git"

output_dir = (Path(_output_dir_arg) if _output_dir_arg else scanner_dir) / ".socket-scans"
facts_path = output_dir / ".socket.facts.json"

# A leftover facts file from a previous run must never masquerade as this scan's results.
facts_path.unlink(missing_ok=True)

# socket-basics is packaged as a GitHub Action, so its configuration arrives as INPUT_<NAME>
# — that is how Actions passes `with:` values, and there are no CLI equivalents for these.
env = {
    **os.environ,
    "INPUT_SOCKET_ORG":              "ynab",
    "INPUT_SOCKET_SECURITY_API_KEY": api_key,
    "INPUT_TRUFFLEHOG_EXCLUDE_DIR":  TRUFFLEHOG_EXCLUDE_DIRS,
}

# The merged config has to sit somewhere the container can see, which rules out the system
# temp dir: on macOS the runtime shares $HOME and little else. output_dir is under $HOME by
# default and already holds this run's artifacts, so it goes there.
warn_if_unshared(output_dir, "the output directory")
output_dir.mkdir(parents=True, exist_ok=True)
config_path = output_dir / ".socket-basics-merged.json"


suppressions_dir = output_dir / ".suppressions"
org_config_path, repo_config_path = fetch_suppressions(suppressions_dir)

try:
    subprocess.check_call(
        [sys.executable, str(merge_script), str(org_config_path), str(repo_config_path),
         str(config_path)],
        stdout=subprocess.DEVNULL,
    )

    # Workspace, repo and branch go in as CLI flags rather than the GITHUB_* environment
    # variables CI supplies.
    #
    # GITHUB_TOKEN is not passed locally, as it's only needed to post comments to a PR.
    cmd = [
        "docker", "run", "--rm",
        "-e", "INPUT_SOCKET_ORG",
        "-e", "INPUT_SOCKET_SECURITY_API_KEY",
        "-e", "INPUT_TRUFFLEHOG_EXCLUDE_DIR",
        "-e", "OUTPUT_DIR=/github/out",
        "-v", f"{target_repo}:/github/workspace",
        "-v", f"{output_dir}:/github/out",
        "-w", "/github/workspace",
        socket_basics_image,
        "--config", f"/github/out/{config_path.name}",
        "--workspace", "/github/workspace",
        "--repo", github_repository,
        "--branch", commit_sha,
    ]

    process = subprocess.Popen(
        cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    for line in process.stdout:
        print(redact_suppressed_rules(line), end="")
    process.wait()
    socket_basics_returncode = process.returncode
finally:
    config_path.unlink(missing_ok=True)
    shutil.rmtree(suppressions_dir, ignore_errors=True)

# --- Print findings summary from facts file ---

rows: list = []
if facts_path.exists():
    try:
        facts = json.loads(facts_path.read_text())
        for component in facts.get("components", []):
            for alert in component.get("alerts", []):
                props = alert.get("props", {})
                loc   = alert.get("location", {})
                rows.append({
                    "repo":                 github_repository,
                    "severity":             (alert.get("severity") or "").strip().lower(),
                    "action":               alert.get("action", ""),
                    "file":                 clean_path(props.get("filePath") or loc.get("path", ""), str(target_repo)),
                    "start_line":           props.get("startLine") or loc.get("start", ""),
                    "end_line":             props.get("endLine") or loc.get("end", ""),
                    "rule":                 props.get("ruleId") or alert.get("title", ""),
                    "description":          alert.get("description", ""),
                    "confidence":           props.get("confidence", ""),
                    "generated_by":         alert.get("generatedBy", ""),
                    "vulnerability_name":   props.get("vulnerabilityName", ""),
                    "vulnerability_category": props.get("vulnerabilityCategory", ""),
                    "cwe":                  props.get("cwe", ""),
                    "owasp":                props.get("owasp", ""),
                    "code_snippet":         props.get("codeSnippet", ""),
                    "fix":                  props.get("fix", ""),
                    "detailed_report":      (props.get("detailedReport") or {}).get("content", ""),
                })

        rows = [
            r for r in rows
            if r["severity"] in ("critical", "high")
            and r["action"] != "ignore"
        ]

        SEVERITY_ORDER = {"critical": 0, "high": 1}
        rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), r["file"], int(r["start_line"] or 0)))

        if rows:
            print(f"\n==> {len(rows)} unsuppressed finding(s)\n")
            col_widths = {
                "severity":     max(8,  max(len(r["severity"])     for r in rows)),
                "file":         max(4,  min(60, max(len(r["file"]) for r in rows))),
                "line":         4,
                "rule":         max(4,  max(len(r["rule"])         for r in rows)),
                "generated_by": max(12, max(len(r["generated_by"]) for r in rows)),
            }
            header = (
                f"  {'SEVERITY':<{col_widths['severity']}}  "
                f"{'FILE':<{col_widths['file']}}  "
                f"{'LINE':>{col_widths['line']}}  "
                f"{'RULE':<{col_widths['rule']}}  "
                f"{'GENERATED BY':<{col_widths['generated_by']}}"
            )
            print(header)
            print("  " + "-" * (len(header) - 2))
            for r in rows:
                file_display = r["file"]
                if len(file_display) > col_widths["file"]:
                    file_display = "…" + file_display[-(col_widths["file"] - 1):]
                print(
                    f"  {r['severity']:<{col_widths['severity']}}  "
                    f"{file_display:<{col_widths['file']}}  "
                    f"{str(r['start_line']):>{col_widths['line']}}  "
                    f"{r['rule']:<{col_widths['rule']}}  "
                    f"{r['generated_by']:<{col_widths['generated_by']}}"
                )

            csv_path = output_dir / ".socket.findings.csv"
            csv_fields = [
                "repo", "severity", "action", "file", "start_line", "end_line",
                "rule", "description", "confidence", "generated_by",
                "vulnerability_name", "vulnerability_category", "cwe", "owasp",
                "code_snippet", "fix",
            ]
            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
            print(f"\n==> CSV saved to {csv_path}")
        else:
            print("\n==> No unsuppressed critical/high findings.")

        print(f"==> Facts file: {facts_path}")
    except Exception as e:
        # An unreadable facts file must not report success — fail with the
        # scanner's exit code (or 1 if the scanner claimed success).
        print(f"\nerror: could not parse facts file: {e}", file=sys.stderr)
        sys.exit(socket_basics_returncode or 1)

if facts_path.exists():
    # Exit based on actionable findings — the facts file is the source of truth.
    sys.exit(1 if rows else 0)
else:
    # No facts file produced — the scan itself failed, not just the upload.
    sys.exit(socket_basics_returncode)
