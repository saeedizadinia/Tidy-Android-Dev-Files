from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from tidy_android.deletion import DeletionService
from tidy_android.models import CandidateKind, Category, CleanupCandidate, RiskLevel


def candidate(path: Path, source_root: Path | None = None) -> CleanupCandidate:
    instant = datetime.now(tz=timezone.utc)
    return CleanupCandidate(
        path=path.resolve(strict=False),
        kind=CandidateKind.DIRECTORY if path.is_dir() else CandidateKind.FILE,
        category=Category.CACHE,
        reasons=("test candidate",),
        size_bytes=path.stat().st_size if path.exists() and path.is_file() else 0,
        modified_at=instant,
        newest_modified_at=instant,
        age_days=100,
        risk=RiskLevel.LOW,
        source_root=(source_root or path.parent).resolve(strict=False),
    )


def test_trash_backend_only_receives_valid_candidates(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    valid = allowed / "valid.cache"
    valid.write_text("data", encoding="utf-8")
    outside = tmp_path / "outside.cache"
    outside.write_text("data", encoding="utf-8")
    calls: list[str] = []
    service = DeletionService(allowed_roots=(allowed,), trash_backend=calls.append)

    results = service.send_to_trash(
        (candidate(valid, allowed), candidate(outside, allowed))
    )

    assert calls == [str(valid.resolve())]
    assert [result.succeeded for result in results] == [True, False]


def test_protected_overlap_is_rejected(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    protected = allowed / "application"
    protected.mkdir(parents=True)
    file = protected / "important.py"
    file.write_text("keep", encoding="utf-8")
    service = DeletionService(
        allowed_roots=(allowed,), protected_paths=(protected,), trash_backend=lambda _path: None
    )
    result = service.validate(candidate(file, allowed))
    assert not result.allowed
    assert "protected" in result.reason.lower()


def test_forged_source_root_is_rejected(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    other = tmp_path / "other"
    allowed.mkdir()
    other.mkdir()
    file = allowed / "cache"
    file.write_text("data", encoding="utf-8")
    service = DeletionService(allowed_roots=(allowed,), trash_backend=lambda _path: None)
    result = service.validate(candidate(file, other))
    assert not result.allowed
    assert "source" in result.reason.lower()


def test_permanent_deletion_continues_after_invalid_item(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    missing = allowed / "missing"
    existing = allowed / "existing"
    existing.write_text("remove", encoding="utf-8")
    missing_candidate = candidate(existing, allowed)
    object.__setattr__(missing_candidate, "path", missing)
    existing_candidate = candidate(existing, allowed)
    service = DeletionService(allowed_roots=(allowed,))

    results = service.delete_permanently((missing_candidate, existing_candidate))

    assert [result.succeeded for result in results] == [False, True]
    assert not existing.exists()


def test_links_are_rejected(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    target = tmp_path / "target"
    allowed.mkdir()
    target.mkdir()
    link = allowed / "link"
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    service = DeletionService(allowed_roots=(allowed,))
    assert not service.validate(candidate(link, allowed)).allowed

