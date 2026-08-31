# ynab-sast-scanner

The reusable GitHub Actions workflow that runs [Socket Basics](https://github.com/SocketDev/socket-basics)
static analysis on every pull request across YNAB repositories.

## Using it

Add this to a repository as `.github/workflows/socket-basics.yml`:

```yaml
name: Socket Basics Security Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  socket-basics-security-scan:
    uses: ynab/ynab-sast-scanner/.github/workflows/socket-basics.yml@main
    secrets:
      SOCKET_SECURITY_API_KEY: ${{ secrets.SOCKET_SECURITY_API_KEY }}
      SAST_SUPPRESSIONS_APP_PRIVATE_KEY: ${{ secrets.SAST_SUPPRESSIONS_APP_PRIVATE_KEY }}
```

Both secrets are organization secrets; nothing per-repo is needed. Name them explicitly as
inputs - inherited secrets are strictly against policy.

`pull_request` is the only supported trigger and the workflow fails fast on anything else.

## Upgrading socket-basics

One pin: `SOCKET_BASICS_IMAGE` in `.github/workflows/socket-basics.yml`. The local scan
script reads that same line, so CI and local scans cannot drift.

Get the digest from [the GHCR package listing](https://github.com/SocketDev/socket-basics/pkgs/container/socket-basics).
Pin the multi-arch index digest, not a platform-specific one, so local arm64 runs work from
the same pin.

## Scanning locally

`scripts/dev/socket-basics.py` scans any repo with the same pinned image that the CI scan uses, 
so a local pass should predict the same in the PR check.

### Prerequisites

```sh
# Docker Desktop — bundles the daemon, CLI and Compose, and runs in the background
brew install --cask docker && open -a Docker

# gh, authenticated — how the suppression configs are read
brew install gh && gh auth login

export SOCKET_SECURITY_API_KEY=<your-key>   # from 1Password
```

Any Docker-compatible runtime works; colima, OrbStack and Rancher Desktop are fine. 
Docker Desktop is only the suggestion because it's a single install with nothing to start by hand.

Suppressions are read with your own `gh` credentials, so there's no secret to distribute: if
you can see the suppressions repo, you can scan.

### Running it

```sh
scripts/dev/socket-basics.py <path-to-repo>

# Read suppressions from a branch, to review a suppressions PR before it merges
scripts/dev/socket-basics.py --suppressions-ref <branch> <path-to-repo>

# Write artifacts somewhere other than ./.socket-scans
scripts/dev/socket-basics.py --output-dir <dir> <path-to-repo>
```

If you use **colima**, note it shares only `$HOME` into its VM by default, so scanning a repo
or writing artifacts outside your home directory fails with a "config file not found" from
inside the container. The script warns when it sees this.
