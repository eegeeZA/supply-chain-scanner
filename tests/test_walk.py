"""Tests for walk_npm_files — scoped packages and --since filter."""

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import walk_npm_files


def _make_stats():
    return {
        "dirs_visited": 0,
        "package_json_checked": 0,
        "lockfiles_checked": 0,
        "node_modules_checked": 0,
        "hidden_lockfiles_checked": 0,
    }


def test_scoped_packages_are_visited(tmp_path):
    """@scope/pkg packages inside node_modules must be yielded as 'installed'."""
    scope_dir = tmp_path / "node_modules" / "@vue" / "reactivity"
    scope_dir.mkdir(parents=True)
    (scope_dir / "package.json").write_text(json.dumps({"name": "@vue/reactivity", "version": "3.0.0"}))

    paths = [(p, k) for p, k in walk_npm_files(str(tmp_path), _make_stats())]
    found = [p for p, k in paths if k == "installed" and "reactivity" in p]
    assert found, f"@vue/reactivity package.json not yielded; got: {paths}"


def test_unscoped_package_is_visited(tmp_path):
    """Regular (unscoped) package inside node_modules is yielded as 'installed'."""
    pkg_dir = tmp_path / "node_modules" / "axios"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.json").write_text(json.dumps({"name": "axios", "version": "1.0.0"}))

    paths = list(walk_npm_files(str(tmp_path), _make_stats()))
    found = [p for p, k in paths if k == "installed" and "axios" in p]
    assert found


def test_since_filter_uses_dir_mtime_when_no_lockfile(tmp_path):
    """--since filter should prune node_modules with old dir mtime even without .package-lock.json."""
    nm = tmp_path / "node_modules" / "old-pkg"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text(json.dumps({"name": "old-pkg", "version": "1.0.0"}))

    # Set the node_modules directory mtime to the past
    old_time = time.time() - 10000
    os.utime(tmp_path / "node_modules", (old_time, old_time))

    # since_ts = now — everything before this should be pruned
    since_ts = time.time() - 1

    paths = list(walk_npm_files(str(tmp_path), _make_stats(), since_ts=since_ts))
    installed = [p for p, k in paths if k == "installed"]
    assert not installed, f"Expected no results after --since filter; got {installed}"
