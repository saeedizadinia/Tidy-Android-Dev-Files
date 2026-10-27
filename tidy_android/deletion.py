from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from send2trash import send2trash

from .models import CleanupCandidate
from .scanner import Scanner


@dataclass(frozen=True, slots=True)
class ValidationResult:
    allowed: bool
    reason: str = ""


@dataclass(frozen=True, slots=True)
class DeletionResult:
    candidate: CleanupCandidate
    succeeded: bool
    message: str


class DeletionService:
    """Revalidate and remove only candidates produced by approved scan roots."""

    def __init__(
        self,
        *,
        allowed_roots: Iterable[Path],
        protected_paths: Iterable[Path] = (),
        application_root: Path | None = None,
        trash_backend: Callable[[str], None] = send2trash,
    ) -> None:
        self.allowed_roots = tuple(self._normalise(path) for path in allowed_roots)
        protected = [self._normalise(path) for path in protected_paths]
        if application_root is not None:
            protected.append(self._normalise(application_root))
        self.protected_paths = tuple(protected)
        self._trash_backend = trash_backend

    def validate(self, candidate: CleanupCandidate) -> ValidationResult:
        path = self._normalise(candidate.path)
        source_root = self._normalise(candidate.source_root)

        if not path.exists():
            return ValidationResult(False, "Path no longer exists")
        if Scanner.is_link_or_reparse(path):
            return ValidationResult(False, "Links and Windows reparse points are never deleted")
        if self._is_dangerous_anchor(path):
            return ValidationResult(False, "Path is a protected filesystem location")
        if not any(self._same(source_root, root) for root in self.allowed_roots):
            return ValidationResult(False, "Candidate source is not an approved scan root")
        if not self._contains(source_root, path):
            return ValidationResult(False, "Candidate escaped its approved scan root")
        if any(self._overlaps(path, protected) for protected in self.protected_paths):
            return ValidationResult(False, "Path overlaps a protected location")
        return ValidationResult(True)

    def send_to_trash(
        self, candidates: Iterable[CleanupCandidate]
    ) -> list[DeletionResult]:
        return self._delete(candidates, permanent=False)

    def delete_permanently(
        self, candidates: Iterable[CleanupCandidate]
    ) -> list[DeletionResult]:
        return self._delete(candidates, permanent=True)

    def _delete(
        self, candidates: Iterable[CleanupCandidate], *, permanent: bool
    ) -> list[DeletionResult]:
        results: list[DeletionResult] = []
        for candidate in candidates:
            validation = self.validate(candidate)
            if not validation.allowed:
                results.append(DeletionResult(candidate, False, validation.reason))
                continue
            try:
                if permanent:
                    if candidate.path.is_dir():
                        shutil.rmtree(candidate.path)
                    else:
                        candidate.path.unlink()
                    message = "Deleted permanently"
                else:
                    self._trash_backend(str(candidate.path))
                    message = "Moved to Recycle Bin"
            except OSError as error:
                results.append(DeletionResult(candidate, False, str(error)))
            else:
                results.append(DeletionResult(candidate, True, message))
        return results

    @staticmethod
    def _normalise(path: Path) -> Path:
        return Path(os.path.abspath(os.path.normpath(path)))

    @staticmethod
    def _key(path: Path) -> str:
        return os.path.normcase(str(path))

    @classmethod
    def _same(cls, left: Path, right: Path) -> bool:
        return cls._key(left) == cls._key(right)

    @classmethod
    def _contains(cls, parent: Path, child: Path) -> bool:
        try:
            common = os.path.commonpath((str(parent), str(child)))
        except ValueError:
            return False
        return cls._key(Path(common)) == cls._key(parent)

    @classmethod
    def _overlaps(cls, candidate: Path, protected: Path) -> bool:
        return cls._contains(candidate, protected) or cls._contains(protected, candidate)

    @staticmethod
    def _is_dangerous_anchor(path: Path) -> bool:
        if path.parent == path:
            return True
        home = Path.home()
        return os.path.normcase(str(path)) == os.path.normcase(str(home))

