from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path


class CandidateKind(StrEnum):
    FILE = "File"
    DIRECTORY = "Directory"


class Category(StrEnum):
    EMPTY = "Empty"
    CACHE = "Cache"
    LOG = "Log"
    TEMPORARY = "Temporary"
    BUILD_OUTPUT = "Build output"
    GRADLE_DISTRIBUTION = "Gradle distribution"
    OLD_IDE = "Old Android Studio"
    SDK = "SDK package"
    SYSTEM_IMAGE = "System image"
    AVD = "Android virtual device"
    OTHER = "Other"


class RiskLevel(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

    @property
    def rank(self) -> int:
        return {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}[self]


class ScanRootKind(StrEnum):
    GRADLE_HOME = "Gradle home"
    ANDROID_HOME = "Android home"
    ANDROID_SDK = "Android SDK"
    ANDROID_STUDIO_LOCAL = "Android Studio local data"
    ANDROID_STUDIO_CONFIG = "Android Studio configuration"
    PROJECTS = "Android projects"
    CUSTOM = "Custom"


@dataclass(frozen=True, slots=True)
class ScanRoot:
    path: Path
    kind: ScanRootKind
    label: str
    protected: bool = False


@dataclass(frozen=True, slots=True)
class CleanupCandidate:
    path: Path
    kind: CandidateKind
    category: Category
    reasons: tuple[str, ...]
    size_bytes: int
    modified_at: datetime
    newest_modified_at: datetime
    age_days: int
    risk: RiskLevel
    source_root: Path

    @property
    def safe_to_bulk_select(self) -> bool:
        return self.risk is RiskLevel.LOW


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    stale_days: int = 90
    roots: tuple[ScanRoot, ...] = ()
    enabled_categories: frozenset[Category] = field(
        default_factory=lambda: frozenset(Category)
    )
    include_high_risk: bool = True

    def __post_init__(self) -> None:
        if self.stale_days < 1:
            raise ValueError("stale_days must be at least 1")

