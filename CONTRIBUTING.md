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

## `repo_artifacts` schema

Use `repo_artifacts` when a campaign poisons victim repos (writes dropper files
that re-execute on the next editor open). Each entry describes one file relative
to the scan root:

```json
"repo_artifacts": [
  {
    "path": ".claude/setup.mjs",
    "match_mode": "hash_or_content",
    "sha256": "<hex>",
    "content_signatures": ["evil-domain.example.com", "UNIQUE_STRING"]
  },
  {
    "path": ".claude/settings.json",
    "match_mode": "json_hook",
    "json_check": {
      "hook_event": "SessionStart",
      "command_regex": "(?:\\.vscode|\\.claude)[\\/]setup\\.mjs"
    }
  },
  {
    "path": ".vscode/tasks.json",
    "match_mode": "json_task",
    "json_check": {
      "run_on": "folderOpen",
      "command_regex": "(?:\\.vscode|\\.claude)[\\/]setup\\.mjs"
    }
  }
]
```

**`match_mode` values:**

- `hash_or_content` — SHA256 hash match emits CRITICAL; IOC string in file
  content emits HIGH (upgraded to CRITICAL if two or more artifacts match).
- `json_hook` — walks `hooks[hook_event][*].hooks[*].command` in a Claude Code
  `settings.json`; regex match emits HIGH (corroborated to CRITICAL as above).
- `json_task` — walks `tasks[*]` in a VS Code `tasks.json`, requires
  `runOn == run_on` and `command`/`args` matching `command_regex`; HIGH with
  corroboration.

**Corroboration rule:** two or more artifact hits from the same incident in the
same scan root emit a single CRITICAL summary finding instead of individual
HIGHs. A SHA256 match is unambiguous and emits CRITICAL even without
corroboration.

## `network_iocs[].type: "string"`

In addition to `"domain"`, `"ip"`, and `"url"`, you may use `"type": "string"`
for high-fidelity unique strings that appear in malware payloads:

```json
{ "type": "string", "value": "UNIQUE_CAMPAIGN_STRING" }
```

All `network_iocs` entries — regardless of `type` — flow through
`_ioc_search_terms()` into shell-profile and persistence scanning
(`host_shell_profiles`, `_persistence_macos`, `_persistence_linux`,
`_persistence_windows`). The `"string"` type makes campaign-specific strings
explicit in the IOC data, but `"domain"` and `"ip"` values are included too.
`host_network()` separately filters to `type: "ip"` only.
