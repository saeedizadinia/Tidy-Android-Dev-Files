from __future__ import annotations

from pathlib import Path

from tidy_android.discovery import WindowsPathDiscovery, version_key
from tidy_android.models import ScanRootKind


def test_version_key_is_numeric() -> None:
    assert version_key("AndroidStudio2026.10.2") > version_key("AndroidStudio2026.2.9")
    assert version_key("unrelated") == ()


def test_discovery_finds_known_paths_and_protects_latest(tmp_path: Path) -> None:
    home = tmp_path / "home"
    local = tmp_path / "local"
    roaming = tmp_path / "roaming"
    sdk = local / "Android" / "Sdk"
    for path in (
        home / ".gradle",
        home / ".android",
        home / "AndroidStudioProjects",
        sdk,
        local / "Google" / "AndroidStudio2025.1",
        local / "Google" / "AndroidStudio2026.2.1",
        roaming / "Google" / "AndroidStudio2025.1",
        roaming / "Google" / "AndroidStudio2026.2.1",
    ):
        path.mkdir(parents=True)

    roots = WindowsPathDiscovery(
        environment={"LOCALAPPDATA": str(local), "APPDATA": str(roaming)},
        home=home,
    ).discover()

    assert any(root.kind is ScanRootKind.GRADLE_HOME for root in roots)
    assert any(root.kind is ScanRootKind.ANDROID_SDK and root.path == sdk for root in roots)
    studio_roots = [root for root in roots if "Android Studio" in root.kind.value]
    assert {root.path.name for root in studio_roots if root.protected} == {
        "AndroidStudio2026.2.1"
    }
    assert all(
        not root.protected
        for root in studio_roots
        if root.path.name == "AndroidStudio2025.1"
    )


def test_custom_roots_are_deduplicated(tmp_path: Path) -> None:
    custom = tmp_path / "project"
    custom.mkdir()
    discovery = WindowsPathDiscovery(environment={}, home=tmp_path / "missing")
    roots = discovery.discover((custom, custom))
    assert len(roots) == 1
    assert roots[0].kind is ScanRootKind.CUSTOM

