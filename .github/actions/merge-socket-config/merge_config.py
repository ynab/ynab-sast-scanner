#!/usr/bin/env python3
"""
Merges the org-level and repo-level Socket Basics suppression configs into one file
for socket-basics --config.

Usage:
    merge_config.py <org.json> <repo.json|missing path> <output.json>

The repo path is allowed not to exist: most repos have no repo-level suppressions.
"""
import json
import re
import sys

# Anchored at line start deliberately: a `//` inside a string (a URL, say) must survive.
_LINE_COMMENT = re.compile(r"^\s*//.*$", re.MULTILINE)


def load(path):
    with open(path) as f:
        return json.loads(_LINE_COMMENT.sub("", f.read()) or "{}")


def merge(org_path, repo_path, merged_path):
    org = load(org_path)

    try:
        repo = load(repo_path)
    except FileNotFoundError:
        repo = {}

    # `_meta` carries suppression justifications for humans and CODEOWNERS review.
    org.pop("_meta", None)
    repo.pop("_meta", None)

    merged = {**org, **repo}

    # Repo-level rule lists are additive: a repo file names only the rules it needs on
    # top of the org list, never a copy of it. Every other key is a plain override.
    for key in merged:
        if key.endswith("_disabled_rules"):
            org_val = org.get(key, "")
            repo_val = repo.get(key, "")
            parts = [r.strip() for r in f"{org_val},{repo_val}".split(",") if r.strip()]
            seen: set = set()
            merged[key] = ",".join(r for r in parts if not (r in seen or seen.add(r)))

    with open(merged_path, "w") as f:
        json.dump(merged, f, indent=2)

    # Counts only — enough to debug a merge without disclosing which rules are off.
    summary = ", ".join(
        f"{k.removesuffix('_disabled_rules')}={len(v.split(','))}"
        for k, v in sorted(merged.items())
        if k.endswith("_disabled_rules") and v
    )
    print(f"Merged Socket config written to {merged_path}")
    print(f"Suppressed rule counts by language: {summary or '(none)'}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(f"usage: {sys.argv[0]} <org.json> <repo.json> <output.json>")
    merge(sys.argv[1], sys.argv[2], sys.argv[3])
