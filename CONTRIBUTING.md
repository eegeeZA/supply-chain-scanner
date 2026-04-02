# Contributing

## Commit messages

Follow the conventions at <https://chris.beams.io/posts/git-commit/> —
imperative subject line under 50 characters, body that explains what and why.

## Changelog

Update `CHANGELOG.md` following <https://keepachangelog.com/en/1.0.0/>. Add new
entries under `[Unreleased]` as you work; move them into a versioned section
when cutting a release.

## Releases

1. Move the `[Unreleased]` entries to a new `[x.y.z] - YYYY-MM-DD` section in
   `CHANGELOG.md`
2. Bump `__version__` in both `scan.py` and `check_findings.py` to match
3. If `iocs.json` changed, re-embed it in `scan.py` (`_EMBEDDED_IOCS`) and
   update `_IOCS_UPDATE_SHA256`:

   ```
   shasum -a 256 iocs.json
   ```

   `_IOCS_UPDATE_SHA256` verifies the **downloaded file** served by
   `_IOCS_UPDATE_URL` — not the embedded Python dict. Forgetting to update it
   causes `--update-iocs` to reject all future downloads with a SHA256 mismatch.

4. Commit, then push the tag:

   ```
   git tag v1.2.3 && git push origin v1.2.3
   ```

   GitHub Actions will create the release automatically.

Use [Semantic Versioning](https://semver.org/) to decide the version number: new
incident or new ecosystem = MINOR, bug fix = PATCH, breaking CLI change = MAJOR.

## Adding a new incident

Add an object to the `"incidents"` array in `iocs.json`, re-embed it in
`scan.py` by updating `_EMBEDDED_IOCS`, then recompute `_IOCS_UPDATE_SHA256`:

```json
{
  "id": "pkg-YYYY-MM-DD",
  "title": "Short title",
  "published": "YYYY-MM-DD",
  "severity": "CRITICAL",
  "source": "https://advisory-url",
  "summary": "One-line description.",
  "package_manager": "npm",
  "malicious_packages": [
    { "name": "pkg-name", "version": "x.y.z", "sha1": "abc123" }
  ],
  "injected_dependency": "evil-dep@1.0.0",
  "safe_versions": ["x.y.z-1"],
  "attack_window_start_utc": "YYYY-MM-DDTHH:MM:SS",
  "attack_window_end_utc": "YYYY-MM-DDTHH:MM:SS",
  "network_iocs": [
    { "type": "domain", "value": "evil.example.com" },
    { "type": "ip", "value": "1.2.3.4", "port": 4444 }
  ],
  "file_iocs": [
    { "platform": "macOS", "path": "~/Library/Caches/evil-file" },
    { "platform": "Linux", "path": "/tmp/evil.py" }
  ],
  "what_to_rotate": ["AWS keys", "NPM tokens"],
  "also_compromised": ["other-tool"]
}
```

**Field notes:**

- `sha1` on `malicious_packages` entries is **informational only** — the scanner
  does not verify tarball checksums; it is recorded for analyst reference.
- `also_compromised` is informational only — not scanned; for operator context.
- For `package_manager: "maven"`, add a `"group_id"` field to each
  `malicious_packages` entry (e.g. `"group_id": "com.example"`). The scanner
  uses it to build the Maven coordinates for the Chocolatey/system check;
  without it the Maven check is silently skipped.
