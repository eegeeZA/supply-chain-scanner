# supply-chain-scanner

![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A forensic incident-response scanner for supply chain compromises. It answers
one question that no existing SCA tool does: **was this machine hit, and what
evidence remains?**

Advisory tools like OSV-Scanner, Trivy, and Grype query a database of known CVEs
against your dependency graph. This tool goes further — it inspects the host
itself for traces that survive even after malware has deleted itself.

## What this scanner does

### Three capabilities found in no other tool

**GHOST detection.** When npm installs a package, it writes a hidden lockfile
(`node_modules/.package-lock.json`) _before_ the postinstall script runs. That
means a postinstall script that deletes its own directory cannot erase this
record. The scanner cross-references this hidden lockfile against what is
currently on disk. A package that was installed and then deleted shows up as a
GHOST — confirmed evidence of execution even with nothing left behind.

**Host forensic checks.** Beyond package files, the scanner inspects:

- Known file paths where malware drops payloads (platform-specific per incident)
- Shell profiles (`.zshrc`, `.bashrc`, etc.) for injected IOC strings
- Persistence mechanisms: macOS LaunchAgents, Linux systemd/cron/XDG autostart,
  Windows startup folders and registry run keys
- npm cache entries — confirms a tarball was downloaded even after a full
  cleanup
- npm install logs — records lifecycle script execution
- Live network connections to known C2 addresses

**`--since` incident-response mode.** When responding to an active incident, you
only need to check installs that happened during the attack window. Passing
`--since 2026-03-31T00:21:00` (or an incident ID like
`--since axios-2026-03-31`) skips everything installed before the window, making
targeted scans approximately 10× faster.

### What else it covers

- All npm lockfile formats: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
  `bun.lock`, `deno.lock`
- Installed packages at all depths: npm flat layout, nested, pnpm virtual store,
  Yarn Berry PnP ZIP archives
- Global package stores: Volta, nvm, fnm, Deno, Bun, npx cache, pnpm CAS
- Docker image layers via `docker save` — no disk extraction required
- Cross-ecosystem: Python, Ruby, Rust, Go, PHP (Composer), Java (Maven),
  Homebrew, Chocolatey
- Live OSV.dev advisory query for npm packages (`--online`)

### Zero external dependencies

`scan.py` is a single file that runs on Python 3.11+ with no packages to
install. The IOC database is embedded — one file to audit, one SHA256 to verify.

---

## The Axios exploit — how this scanner checks for it

On 31 March 2026, between 00:21 and 03:15 UTC, a threat actor published two
malicious versions of the axios npm package (`1.14.1` and `0.30.4`). Each
version contained an injected dependency (`plain-crypto-js@4.2.1`) that deployed
a credential harvester and a cross-platform remote access trojan. The packages
reached 100M+ weekly downloads before being yanked — a window of approximately
three hours.

The same attacker also compromised `trivy`, `kics`, `litellm`, and `telnyx`
during the same period.

**What the scanner checks for this incident:**

| Check           | What it looks for                                                                                    |
|-----------------|------------------------------------------------------------------------------------------------------|
| Lockfiles       | `axios@1.14.1` or `axios@0.30.4` resolved in any lockfile                                            |
| `node_modules`  | Either malicious version installed at any depth                                                      |
| Hidden lockfile | GHOST state — axios was installed but the directory is now gone                                      |
| npm cache       | Tarball for the malicious version fetched to `~/.npm/_cacache/`                                      |
| npm logs        | `postinstall` lifecycle execution recorded in `~/.npm/_logs/`                                        |
| File artifacts  | `/Library/Caches/com.apple.act.mond` (macOS), `/tmp/ld.py` (Linux), `%PROGRAMDATA%\wt.exe` (Windows) |
| Shell profiles  | IOC strings injected into `.zshrc`, `.bashrc`, or equivalent                                         |
| Persistence     | LaunchAgents (macOS), systemd units (Linux), startup entries (Windows)                               |
| Live network    | Active connections to `142.11.206.73:8000` or `sfrclak.com`                                          |

If you were running `npm install` between 00:21 and 03:15 UTC on 31 March 2026
and axios was a direct or transitive dependency, use `--since` to scope the scan
to that window:

```bash
python3 scan.py ~/dev --since axios-2026-03-31
```

If CRITICAL or HIGH findings are reported, rotate: npm tokens, AWS/Azure/GCP
credentials, SSH keys, database passwords, and API tokens.

---

## Quickstart

```bash
# Scan your development directory
python3 scan.py ~/dev

# Incident-response mode — only checks installs from the attack window
python3 scan.py ~/dev --since axios-2026-03-31
```

No installation required. Python 3.11 or later, standard library only.

---

## All flags and options

### Positional argument

| Argument | Description                                                                          |
|----------|--------------------------------------------------------------------------------------|
| `ROOT`   | Directory to scan. Defaults to `/` (full OS scan). Omit when using `--docker` alone. |

### Options

| Flag                   | Default           | Description                                                                                                                                                                     |
|------------------------|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--workers N`          | min(CPU count, 8) | Number of worker threads for parallel file parsing                                                                                                                              |
| `--iocs FILE`          | (embedded)        | Path to a custom IOC database JSON file                                                                                                                                         |
| `--since ISO_OR_ID`    | —                 | Incident-response mode: only scan `node_modules` modified on or after this timestamp. Accepts an ISO datetime (`2026-03-31T00:21:00`) or an incident ID (`axios-2026-03-31`)    |
| `--update-iocs`        | —                 | Download a fresh `iocs.json` from the upstream URL, verify its SHA256, write to disk, and exit                                                                                  |
| `--docker [IMAGE ...]` | —                 | Scan Docker images via `docker save`. Pass specific image names or omit names to scan all local images                                                                          |
| `--top-layers N`       | 5                 | Number of most-recent Docker image layers to scan. Use `0` to scan all layers                                                                                                   |
| `--online`             | —                 | Query OSV.dev live for malware advisories on all discovered npm packages                                                                                                        |
| `--host` / `--no-host` | auto              | Enable or disable host-level forensic checks (file artifacts, shell profiles, persistence, npm cache, npm logs). Auto-enabled when `ROOT` is `/` or omitted; disabled otherwise |

### Output formats

Flags are mutually exclusive. Default is human-readable coloured text.

| Flag      | Output                                                                   |
|-----------|--------------------------------------------------------------------------|
| `--json`  | Machine-readable JSON with `summary` and `findings` array — pipe to `jq` |
| `--sarif` | SARIF 2.1.0 for GitHub Code Scanning or VS Code                          |
| `--junit` | JUnit XML for GitLab CI or Jenkins                                       |
| `--html`  | Self-contained HTML report — no internet connection required             |

### Exit codes

| Code | Meaning                                                             |
|------|---------------------------------------------------------------------|
| `0`  | Clean — no findings of any severity                                 |
| `1`  | CRITICAL or HIGH finding — act immediately                          |
| `2`  | Scan error (bad arguments, missing files)                           |
| `3`  | WARNING only — susceptible configuration, not confirmed compromised |

### Examples

```bash
# Full OS scan
python3 scan.py

# Target a specific directory
python3 scan.py ~/dev

# Incident-response mode
python3 scan.py ~/dev --since 2026-03-31T00:21:00
python3 scan.py ~/dev --since axios-2026-03-31

# Machine-readable output
python3 scan.py ~/dev --json
python3 scan.py ~/dev --json | jq '.findings[] | select(.severity == "CRITICAL")'
python3 scan.py ~/dev --json | jq '.stats'

# GitHub Code Scanning
python3 scan.py ~/dev --sarif > results.sarif

# Offline report
python3 scan.py ~/dev --html > report.html

# Docker scanning
python3 scan.py --docker                            # all local images
python3 scan.py --docker nginx:latest node:18-slim  # specific images
python3 scan.py ~/dev --docker                      # filesystem + Docker

# Live OSV.dev advisory check
python3 scan.py ~/dev --online

# Use a custom IOC database
python3 scan.py ~/dev --iocs /path/to/custom-iocs.json

# Update the embedded IOC database
python3 scan.py --update-iocs
```

---

## CI integration

The repository includes a ready-to-use GitHub Actions workflow at
`.github/workflows/scan.yml`. Copy it to your repository to:

- Run the scanner on every push and pull request
- Upload findings to GitHub Code Scanning (visible in the Security tab)
- Fail the build if any CRITICAL or HIGH findings are present
- Retain the raw JSON result as a workflow artifact for 30 days

The build gate is implemented by `check_findings.py`, which reads the JSON
output, converts it to SARIF 2.1.0 for upload to Code Scanning, and exits 1 if
any CRITICAL or HIGH findings are present. The workflow handles non-zero exit
codes correctly — SARIF is always uploaded even when the build ultimately fails
on findings.

By default, `scan.py .` in CI runs in **repo-scoped mode** (host forensic checks
disabled) so build results depend only on repository content, not runner state.
Pass `--host` to enable full host forensics in a dedicated IR scan job.

---

## Interpreting results

| Severity | Meaning                                                                                        | Action                                                                                                                    |
|----------|------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| CRITICAL | Malicious package confirmed installed or executed                                              | Treat the machine as compromised. Rotate all credentials (see the incident's `what_to_rotate` list). Isolate if possible. |
| HIGH     | Strong forensic evidence (GHOST, npm cache/log, file artifact, persistence)                    | High confidence of prior execution even if the package is no longer present. Rotate credentials, investigate further.     |
| WARNING  | Susceptible configuration (floating version range, missing lockfile, `ignore-scripts` not set) | No confirmed compromise, but the configuration allows it. Tighten the config.                                             |

If a scan returns CRITICAL or HIGH for the axios incident, rotate: npm tokens,
AWS/Azure/GCP cloud credentials, SSH keys, database passwords, and any API
tokens that were accessible on the machine during the attack window.

---

## Complementary tools

This scanner covers forensic IR. Run these alongside it for full coverage:

| Tool                                                 | What it adds                                                                                      | When to use                               |
|------------------------------------------------------|---------------------------------------------------------------------------------------------------|-------------------------------------------|
| [OSV-Scanner](https://google.github.io/osv-scanner/) | CVE advisory scanning for 11+ ecosystems; offline-capable; lockfile and Docker image CVE scanning | Scheduled CI gate, pre-merge checks       |
| [Trivy](https://github.com/aquasecurity/trivy)       | Docker/K8s/IaC scanning; OS package CVEs inside images; secrets detection in source               | Container image hardening, IaC security   |
| [Grype](https://github.com/anchore/grype)            | Lightweight CVE scanner; offline DB; pairs with Syft for SBOM generation                          | Offline/air-gapped CVE auditing           |
| [Socket.dev](https://socket.dev)                     | Behavioural static analysis of npm packages for malicious code patterns                           | Pre-install PR gate (SaaS)                |
| npm audit                                            | Built-in CVE check against npm advisory DB                                                        | Quick lockfile check, no install required |

---

## Requirements

- Python 3.11 or later
- No packages to install — standard library only
- `docker` CLI in `PATH` for `--docker` scanning (optional)
- `lsof` / `ss` / `netstat` for live network connection checks (optional,
  OS-provided)
