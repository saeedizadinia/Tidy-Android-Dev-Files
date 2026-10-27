from __future__ import annotations

import os
import re
import stat
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

from .models import (
    CandidateKind,
    Category,
    CleanupCandidate,
    RiskLevel,
    ScanPolicy,
    ScanRoot,
    ScanRootKind,
)


ProgressCallback = Callable[[str], None]
_GRADLE_VERSION = re.compile(r"gradle-(?P<version>\d+(?:\.\d+)+)(?:-|$)")
_PLAIN_VERSION = re.compile(r"^\d+(?:\.\d+)+(?:[-+].*)?$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_PROJECT_PRUNE = {".git", ".idea", ".venv", "node_modules", "__pycache__"}
_PROJECT_OUTPUTS = {"build", ".gradle", ".cxx", ".externalNativeBuild", "captures"}


class ScanCancelled(RuntimeError):
    pass


class Scanner:
    """Classify bounded Android/Gradle paths into reviewable cleanup candidates."""

    def __init__(self, *, now: Callable[[], float] = time.time) -> None:
        self._now = now
        self.last_errors: list[str] = []
        self._cancel_event = Event()
        self._policy = ScanPolicy()

    def scan(
        self,
        policy: ScanPolicy,
        progress: ProgressCallback | None = None,
        cancel_event: Event | None = None,
    ) -> list[CleanupCandidate]:
        self._policy = policy
        self._cancel_event = cancel_event or Event()
        self.last_errors = []
        report = progress or (lambda _message: None)
        candidates: list[CleanupCandidate] = []

        referenced_versions = self._find_referenced_gradle_versions(policy.roots)
        for root in policy.roots:
            self._check_cancelled()
            report(f"Scanning {root.label}")
            try:
                self._scan_root(root, referenced_versions, candidates)
            except ScanCancelled:
                raise
            except OSError as error:
                self.last_errors.append(f"{root.path}: {error}")

        filtered = [
            candidate
            for candidate in candidates
            if candidate.category in policy.enabled_categories
            and (policy.include_high_risk or candidate.risk is not RiskLevel.HIGH)
        ]
        return self.coalesce_candidates(filtered)

    def _scan_root(
        self,
        root: ScanRoot,
        referenced_versions: set[str],
        candidates: list[CleanupCandidate],
    ) -> None:
        if root.kind is ScanRootKind.GRADLE_HOME:
            self._scan_gradle_home(root, referenced_versions, candidates)
        elif root.kind is ScanRootKind.ANDROID_HOME:
            self._scan_android_home(root, candidates)
        elif root.kind is ScanRootKind.ANDROID_SDK:
            self._scan_sdk(root, candidates)
        elif root.kind in {
            ScanRootKind.ANDROID_STUDIO_LOCAL,
            ScanRootKind.ANDROID_STUDIO_CONFIG,
        }:
            self._scan_android_studio(root, candidates)
        elif root.kind in {ScanRootKind.PROJECTS, ScanRootKind.CUSTOM}:
            self._scan_projects(root, candidates)

        if root.kind in {
            ScanRootKind.ANDROID_HOME,
            ScanRootKind.PROJECTS,
            ScanRootKind.CUSTOM,
        }:
            for path in self._iter_empty_directories(root.path, max_depth=4):
                self._add_candidate(
                    candidates,
                    path,
                    root,
                    Category.EMPTY,
                    RiskLevel.LOW,
                    ("Directory is empty",),
                )

    def _scan_gradle_home(
        self,
        root: ScanRoot,
        referenced_versions: set[str],
        candidates: list[CleanupCandidate],
    ) -> None:
        for parent_name in ("caches", "daemon"):
            parent = root.path / parent_name
            for child in self._safe_children(parent):
                if child.name in referenced_versions or (
                    _PLAIN_VERSION.match(child.name) and child.name in referenced_versions
                ):
                    continue
                self._add_candidate(
                    candidates,
                    child,
                    root,
                    Category.CACHE,
                    RiskLevel.LOW,
                    (f"Unused Gradle {parent_name} entry",),
                )

        for name in ("native", "notifications", "workers"):
            self._add_candidate(
                candidates,
                root.path / name,
                root,
                Category.CACHE,
                RiskLevel.LOW,
                ("Regenerable Gradle cache",),
            )

        distributions = root.path / "wrapper" / "dists"
        for distribution in self._safe_children(distributions):
            match = _GRADLE_VERSION.search(distribution.name)
            version = match.group("version") if match else None
            if version and version in referenced_versions:
                continue
            self._add_candidate(
                candidates,
                distribution,
                root,
                Category.GRADLE_DISTRIBUTION,
                RiskLevel.MEDIUM,
                ("Gradle distribution is not referenced by a discovered project",),
            )

    def _scan_android_home(
        self, root: ScanRoot, candidates: list[CleanupCandidate]
    ) -> None:
        for name in ("cache", "build-cache", "tmp", "temp"):
            self._add_candidate(
                candidates,
                root.path / name,
                root,
                Category.CACHE if "cache" in name else Category.TEMPORARY,
                RiskLevel.LOW,
                ("Regenerable Android tool data",),
            )
        for avd in self._safe_children(root.path / "avd"):
            if avd.suffix.lower() not in {".avd", ".ini"}:
                continue
            self._add_candidate(
                candidates,
                avd,
                root,
                Category.AVD,
                RiskLevel.HIGH,
                ("Android virtual device has not changed recently",),
            )

    def _scan_sdk(self, root: ScanRoot, candidates: list[CleanupCandidate]) -> None:
        for name in ("temp", ".temp", "cache", ".cache"):
            self._add_candidate(
                candidates,
                root.path / name,
                root,
                Category.TEMPORARY if "temp" in name else Category.CACHE,
                RiskLevel.LOW,
                ("Regenerable Android SDK temporary data",),
            )

        for parent_name in ("platforms", "build-tools", "sources", "ndk", "cmake"):
            for package in self._safe_children(root.path / parent_name):
                self._add_candidate(
                    candidates,
                    package,
                    root,
                    Category.SDK,
                    RiskLevel.HIGH,
                    (f"Installed {parent_name} package has not changed recently",),
                )
        for image in self._safe_children(root.path / "system-images"):
            self._add_candidate(
                candidates,
                image,
                root,
                Category.SYSTEM_IMAGE,
                RiskLevel.HIGH,
                ("Installed Android system image has not changed recently",),
            )

    def _scan_android_studio(
        self, root: ScanRoot, candidates: list[CleanupCandidate]
    ) -> None:
        if not root.protected:
            risk = (
                RiskLevel.MEDIUM
                if root.kind is ScanRootKind.ANDROID_STUDIO_LOCAL
                else RiskLevel.HIGH
            )
            reason = (
                "Belongs to an older Android Studio version"
                if risk is RiskLevel.MEDIUM
                else "Older Android Studio settings may contain plugins and preferences"
            )
            self._add_candidate(
                candidates,
                root.path,
                root,
                Category.OLD_IDE,
                risk,
                (reason,),
                force=True,
            )
            return

        for name in ("cache", "caches", "log", "logs", "tmp", "temp", "compile-server"):
            category = Category.LOG if name.startswith("log") else Category.CACHE
            if name in {"tmp", "temp"}:
                category = Category.TEMPORARY
            self._add_candidate(
                candidates,
                root.path / name,
                root,
                category,
                RiskLevel.LOW,
                ("Regenerable data for the current Android Studio version",),
            )

    def _scan_projects(
        self, root: ScanRoot, candidates: list[CleanupCandidate]
    ) -> None:
        for output in self._iter_project_outputs(root.path):
            self._add_candidate(
                candidates,
                output,
                root,
                Category.BUILD_OUTPUT,
                RiskLevel.LOW,
                ("Generated project output can be rebuilt",),
            )

    def _add_candidate(
        self,
        candidates: list[CleanupCandidate],
        path: Path,
        root: ScanRoot,
        category: Category,
        risk: RiskLevel,
        reasons: tuple[str, ...],
        *,
        force: bool = False,
    ) -> None:
        self._check_cancelled()
        try:
            if not path.exists() or self.is_link_or_reparse(path):
                return
            metrics = self.path_metrics(path, self._cancel_event)
            if metrics is None:
                return
            size_bytes, newest_mtime, empty = metrics
            path_mtime = path.stat(follow_symlinks=False).st_mtime
        except (OSError, PermissionError) as error:
            self.last_errors.append(f"{path}: {error}")
            return

        age_days = max(0, int((self._now() - newest_mtime) // 86_400))
        if not force and not empty and age_days < self._policy.stale_days:
            return
        final_reasons = list(reasons)
        if empty:
            final_reasons.append("Directory is empty" if path.is_dir() else "File is empty")
        elif age_days >= self._policy.stale_days:
            final_reasons.append(f"No modifications for {age_days} days")

        candidates.append(
            CleanupCandidate(
                path=path.resolve(strict=False),
                kind=CandidateKind.DIRECTORY if path.is_dir() else CandidateKind.FILE,
                category=category,
                reasons=tuple(dict.fromkeys(final_reasons)),
                size_bytes=size_bytes,
                modified_at=datetime.fromtimestamp(path_mtime, tz=timezone.utc),
                newest_modified_at=datetime.fromtimestamp(newest_mtime, tz=timezone.utc),
                age_days=age_days,
                risk=risk,
                source_root=root.path,
            )
        )

    def _find_referenced_gradle_versions(self, roots: Iterable[ScanRoot]) -> set[str]:
        versions: set[str] = set()
        for root in roots:
            if root.kind not in {ScanRootKind.PROJECTS, ScanRootKind.CUSTOM}:
                continue
            for properties in self._iter_named_files(
                root.path, "gradle-wrapper.properties", max_depth=7
            ):
                self._check_cancelled()
                try:
                    text = properties.read_text(encoding="utf-8", errors="replace")
                except OSError as error:
                    self.last_errors.append(f"{properties}: {error}")
                    continue
                match = _GRADLE_VERSION.search(text)
                if match:
                    versions.add(match.group("version"))
        return versions

    def _iter_named_files(
        self, root: Path, filename: str, *, max_depth: int
    ) -> Iterator[Path]:
        for current, directories, files in os.walk(root, followlinks=False):
            self._check_cancelled()
            current_path = Path(current)
            depth = len(current_path.relative_to(root).parts)
            directories[:] = [
                name
                for name in directories
                if name not in _PROJECT_PRUNE
                and not self.is_link_or_reparse(current_path / name)
            ]
            if depth >= max_depth:
                directories[:] = []
            if filename in files:
                yield current_path / filename

    def _iter_project_outputs(self, root: Path) -> Iterator[Path]:
        for current, directories, _files in os.walk(root, followlinks=False):
            self._check_cancelled()
            current_path = Path(current)
            depth = len(current_path.relative_to(root).parts)
            kept: list[str] = []
            for name in directories:
                path = current_path / name
                if name in _PROJECT_PRUNE or self.is_link_or_reparse(path):
                    continue
                if name in _PROJECT_OUTPUTS:
                    yield path
                    continue
                kept.append(name)
            directories[:] = kept if depth < 7 else []

    def _iter_empty_directories(self, root: Path, *, max_depth: int) -> Iterator[Path]:
        for current, directories, files in os.walk(root, followlinks=False):
            self._check_cancelled()
            current_path = Path(current)
            depth = len(current_path.relative_to(root).parts)
            directories[:] = [
                name
                for name in directories
                if name not in _PROJECT_PRUNE
                and not self.is_link_or_reparse(current_path / name)
            ]
            if depth >= max_depth:
                directories[:] = []
            if current_path != root and not directories and not files:
                yield current_path

    def _safe_children(self, path: Path) -> tuple[Path, ...]:
        self._check_cancelled()
        try:
            if not path.is_dir() or self.is_link_or_reparse(path):
                return ()
            return tuple(path.iterdir())
        except OSError as error:
            self.last_errors.append(f"{path}: {error}")
            return ()

    def _check_cancelled(self) -> None:
        if self._cancel_event.is_set():
            raise ScanCancelled("Scan cancelled")

    @staticmethod
    def is_link_or_reparse(path: Path) -> bool:
        try:
            details = path.lstat()
        except OSError:
            return False
        return stat.S_ISLNK(details.st_mode) or bool(
            getattr(details, "st_file_attributes", 0) & _REPARSE_POINT
        )

    @classmethod
    def path_metrics(
        cls, path: Path, cancel_event: Event | None = None
    ) -> tuple[int, float, bool] | None:
        """Return (bytes, newest mtime, empty) without following links."""
        cancel = cancel_event or Event()
        if cls.is_link_or_reparse(path):
            return None
        details = path.stat(follow_symlinks=False)
        if path.is_file():
            return details.st_size, details.st_mtime, details.st_size == 0

        size = 0
        newest = details.st_mtime
        entries = 0
        for current, directories, files in os.walk(path, followlinks=False):
            if cancel.is_set():
                raise ScanCancelled("Scan cancelled")
            current_path = Path(current)
            safe_directories: list[str] = []
            for name in directories:
                child = current_path / name
                if cls.is_link_or_reparse(child):
                    continue
                safe_directories.append(name)
                entries += 1
                try:
                    newest = max(newest, child.stat(follow_symlinks=False).st_mtime)
                except OSError:
                    continue
            directories[:] = safe_directories
            for name in files:
                child = current_path / name
                if cls.is_link_or_reparse(child):
                    continue
                entries += 1
                try:
                    child_details = child.stat(follow_symlinks=False)
                except OSError:
                    continue
                size += child_details.st_size
                newest = max(newest, child_details.st_mtime)
        return size, newest, entries == 0

    @staticmethod
    def coalesce_candidates(
        candidates: Iterable[CleanupCandidate],
    ) -> list[CleanupCandidate]:
        unique: dict[str, CleanupCandidate] = {}
        for candidate in candidates:
            key = os.path.normcase(str(candidate.path))
            existing = unique.get(key)
            if existing is None or candidate.risk.rank < existing.risk.rank:
                unique[key] = candidate

        ordered = sorted(
            unique.values(),
            key=lambda item: (len(item.path.parts), os.path.normcase(str(item.path))),
        )
        result: list[CleanupCandidate] = []
        for candidate in ordered:
            if any(_is_relative_to(candidate.path, parent.path) for parent in result):
                continue
            result.append(candidate)
        return result


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return path != parent
    except ValueError:
        return False

