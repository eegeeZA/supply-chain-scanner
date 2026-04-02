# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-04-02

### Added

- npm scanning: package.json declared ranges, all lockfile formats
  (package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, deno.lock), and
  installed packages at all depths including pnpm virtual store and Yarn Berry
  PnP ZIP archives
- GHOST and STUB detection: cross-references the hidden lockfile written by npm
  before postinstall runs against what is currently on disk — catches malware
  that deleted itself after executing
- Host forensic checks: known malware drop paths, shell profile tampering,
  persistence mechanisms (LaunchAgents, systemd, cron, Windows
  startup/registry), npm cache evidence, npm log evidence, and live network
  connections to known C2 addresses
- Docker image layer scanning via `docker save` with no disk extraction
- Cross-ecosystem scanning: Python, Ruby, Rust, Go, PHP (Composer), Java
  (Maven), Homebrew, and Chocolatey
- Global package store checks: Volta, nvm, fnm, Deno, Bun, npx cache, pnpm CAS
- `--since` incident-response mode: limits the scan to packages installed on or
  after a given timestamp, approximately 10× faster for targeted scans
- `--online` flag: queries OSV.dev live for malware advisories on all discovered
  npm packages
- Multiple output formats: human-readable (default), `--json`, `--sarif`,
  `--junit`, `--html`
- GitHub Actions CI workflow with SARIF upload to GitHub Code Scanning
- Tag-triggered release workflow that publishes GitHub Releases from CHANGELOG
- IOC database update mechanism (`--update-iocs`) with SHA256 verification
- Embedded IOC database: axios npm supply chain compromise (2026-03-31)
