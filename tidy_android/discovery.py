from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path

from .models import ScanRoot, ScanRootKind


_STUDIO_PATTERN = re.compile(r"^AndroidStudio(?P<version>\d+(?:\.\d+)*)")


def version_key(name: str) -> tuple[int, ...]:
    """Return a numeric version key for an Android Studio directory name."""
    match = _STUDIO_PATTERN.match(name)
    if not match:
        return ()
    return tuple(int(part) for part in match.group("version").split("."))


class WindowsPathDiscovery:
    """Discover well-known Android development locations without scanning disks."""

    def __init__(
        self,
        *,
        environment: Mapping[str, str] | None = None,
        home: Path | None = None,
    ) -> None:
        self.environment = dict(os.environ if environment is None else environment)
        self.home = Path(home or Path.home())

    def discover(self, custom_roots: Iterable[Path] = ()) -> tuple[ScanRoot, ...]:
        candidates: list[ScanRoot] = []

        self._append(
            candidates,
            self.home / ".gradle",
            ScanRootKind.GRADLE_HOME,
            "Gradle user home",
        )
        self._append(
            candidates,
            self.home / ".android",
            ScanRootKind.ANDROID_HOME,
            "Android user home",
        )

        sdk_paths: list[Path] = []
        for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
            value = self.environment.get(variable)
            if value:
                sdk_paths.append(Path(value))
        local_app_data = self._environment_path("LOCALAPPDATA")
        roaming_app_data = self._environment_path("APPDATA")
        if local_app_data:
            sdk_paths.append(local_app_data / "Android" / "Sdk")
        for sdk_path in sdk_paths:
            self._append(
                candidates,
                sdk_path,
                ScanRootKind.ANDROID_SDK,
                "Android SDK",
            )

        studio_paths: list[tuple[Path, ScanRootKind]] = []
        if local_app_data:
            studio_paths.extend(
                (path, ScanRootKind.ANDROID_STUDIO_LOCAL)
                for path in (local_app_data / "Google").glob("AndroidStudio*")
            )
        if roaming_app_data:
            studio_paths.extend(
                (path, ScanRootKind.ANDROID_STUDIO_CONFIG)
                for path in (roaming_app_data / "Google").glob("AndroidStudio*")
            )

        versions = [version_key(path.name) for path, _ in studio_paths]
        latest_version = max((value for value in versions if value), default=())
        for path, kind in studio_paths:
            self._append(
                candidates,
                path,
                kind,
                f"{kind.value}: {path.name}",
                protected=bool(latest_version and version_key(path.name) == latest_version),
            )

        self._append(
            candidates,
            self.home / "AndroidStudioProjects",
            ScanRootKind.PROJECTS,
            "Android Studio projects",
        )
        for path in custom_roots:
            self._append(candidates, Path(path), ScanRootKind.CUSTOM, "Custom root")

        return self._deduplicate(candidates)

    def _environment_path(self, name: str) -> Path | None:
        value = self.environment.get(name)
        return Path(value) if value else None

    @staticmethod
    def _append(
        roots: list[ScanRoot],
        path: Path,
        kind: ScanRootKind,
        label: str,
        *,
        protected: bool = False,
    ) -> None:
        try:
            if path.exists() and path.is_dir():
                roots.append(
                    ScanRoot(
                        path=path.resolve(strict=False),
                        kind=kind,
                        label=label,
                        protected=protected,
                    )
                )
        except OSError:
            return

    @staticmethod
    def _deduplicate(roots: Iterable[ScanRoot]) -> tuple[ScanRoot, ...]:
        result: list[ScanRoot] = []
        seen: set[str] = set()
        for root in roots:
            key = os.path.normcase(str(root.path))
            if key in seen:
                continue
            seen.add(key)
            result.append(root)
        return tuple(result)

