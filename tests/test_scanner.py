from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

import pytest

from conftest import age_tree
from tidy_android.models import (
    CandidateKind,
    Category,
    CleanupCandidate,
    RiskLevel,
    ScanPolicy,
    ScanRoot,
    ScanRootKind,
)
from tidy_android.scanner import ScanCancelled, Scanner


NOW = 2_000_000_000.0
OLD = NOW - 120 * 86_400


def root(path: Path, kind: ScanRootKind, *, protected: bool = False) -> ScanRoot:
    return ScanRoot(path.resolve(), kind, kind.value, protected)


def test_scanner_finds_stale_build_empty_and_unreferenced_gradle(tmp_path: Path) -> None:
    projects = tmp_path / "projects"
    project = projects / "Example"
    build = project / "app" / "build"
    build.mkdir(parents=True)
    (build / "classes.bin").write_bytes(b"generated")
    empty = project / "unused-empty"
    empty.mkdir()
    wrapper = project / "gradle" / "wrapper"
    wrapper.mkdir(parents=True)
    (wrapper / "gradle-wrapper.properties").write_text(
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.10-bin.zip",
        encoding="utf-8",
    )

    gradle_home = tmp_path / ".gradle"
    used_dist = gradle_home / "wrapper" / "dists" / "gradle-8.10-bin"
    unused_dist = gradle_home / "wrapper" / "dists" / "gradle-8.5-bin"
    used_dist.mkdir(parents=True)
    unused_dist.mkdir(parents=True)
    (used_dist / "used.zip.ok").write_text("ok", encoding="utf-8")
    (unused_dist / "old.zip").write_text("old", encoding="utf-8")
    age_tree(projects, OLD)
    age_tree(gradle_home, OLD)

    scanner = Scanner(now=lambda: NOW)
    candidates = scanner.scan(
        ScanPolicy(
            stale_days=90,
            roots=(
                root(projects, ScanRootKind.PROJECTS),
                root(gradle_home, ScanRootKind.GRADLE_HOME),
            ),
        )
    )
    paths = {candidate.path for candidate in candidates}

    assert build.resolve() in paths
    assert empty.resolve() in paths
    assert unused_dist.resolve() in paths
    assert used_dist.resolve() not in paths
    assert next(item for item in candidates if item.path == build.resolve()).risk is RiskLevel.LOW


def test_recent_nonempty_output_is_not_a_candidate(tmp_path: Path) -> None:
    projects = tmp_path / "projects"
    build = projects / "Example" / "build"
    build.mkdir(parents=True)
    (build / "recent.txt").write_text("new", encoding="utf-8")
    age_tree(projects, NOW - 5 * 86_400)

    candidates = Scanner(now=lambda: NOW).scan(
        ScanPolicy(roots=(root(projects, ScanRootKind.PROJECTS),))
    )
    assert build.resolve() not in {candidate.path for candidate in candidates}


def test_old_ide_risk_depends_on_data_type(tmp_path: Path) -> None:
    local = tmp_path / "local" / "AndroidStudio2025.1"
    config = tmp_path / "roaming" / "AndroidStudio2025.1"
    local.mkdir(parents=True)
    config.mkdir(parents=True)
    age_tree(tmp_path, OLD)

    candidates = Scanner(now=lambda: NOW).scan(
        ScanPolicy(
            roots=(
                root(local, ScanRootKind.ANDROID_STUDIO_LOCAL),
                root(config, ScanRootKind.ANDROID_STUDIO_CONFIG),
            )
        )
    )
    risks = {candidate.path: candidate.risk for candidate in candidates}
    assert risks[local.resolve()] is RiskLevel.MEDIUM
    assert risks[config.resolve()] is RiskLevel.HIGH


def test_high_risk_candidates_can_be_hidden(tmp_path: Path) -> None:
    android_home = tmp_path / ".android"
    avd = android_home / "avd" / "Pixel.avd"
    avd.mkdir(parents=True)
    (avd / "userdata.img").write_bytes(b"data")
    age_tree(android_home, OLD)
    candidates = Scanner(now=lambda: NOW).scan(
        ScanPolicy(
            roots=(root(android_home, ScanRootKind.ANDROID_HOME),),
            include_high_risk=False,
        )
    )
    assert all(candidate.risk is not RiskLevel.HIGH for candidate in candidates)


def test_scan_honours_pre_cancelled_event(tmp_path: Path) -> None:
    projects = tmp_path / "projects"
    projects.mkdir()
    cancelled = Event()
    cancelled.set()
    with pytest.raises(ScanCancelled):
        Scanner(now=lambda: NOW).scan(
            ScanPolicy(roots=(root(projects, ScanRootKind.PROJECTS),)),
            cancel_event=cancelled,
        )


def test_metrics_do_not_follow_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "data").write_bytes(b"1234")
    link = tmp_path / "link"
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks is not available")
    assert Scanner.path_metrics(link) is None


def test_coalescing_removes_nested_duplicate(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    instant = datetime.fromtimestamp(OLD, tz=timezone.utc)

    def candidate(path: Path) -> CleanupCandidate:
        return CleanupCandidate(
            path=path,
            kind=CandidateKind.DIRECTORY,
            category=Category.CACHE,
            reasons=("test",),
            size_bytes=0,
            modified_at=instant,
            newest_modified_at=instant,
            age_days=120,
            risk=RiskLevel.LOW,
            source_root=tmp_path,
        )

    assert Scanner.coalesce_candidates((candidate(child), candidate(parent))) == [
        candidate(parent)
    ]

