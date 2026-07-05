"""FLE-OS-001 — the running OS matches the declared target.

For anonymity work the highest-consequence mistake is doing sensitive things on
the *wrong* operating system: firing up a real browser on your host instead of
Tails, or on the Whonix Gateway instead of the Workstation. This control detects
what you are actually running and fails if it is not what you declared in
`os.expect`.

Detection understands the amnesic/anonymity systems the community uses (Tails,
Whonix Gateway/Workstation, Qubes) plus ordinary distros and Windows/macOS.
"""

from __future__ import annotations

import platform
from pathlib import Path

from ..model import State
from .base import Provider, ProviderContext
from .registry import register

# Umbrella terms a config may declare instead of an exact OS id.
OS_UMBRELLA: dict[str, set[str]] = {
    "whonix": {"whonix", "whonix-gateway", "whonix-workstation"},
    "anonymity": {"tails", "whonix", "whonix-gateway", "whonix-workstation", "qubes"},
    "linux": {
        "tails", "whonix", "whonix-gateway", "whonix-workstation", "qubes",
        "debian", "ubuntu", "fedora", "arch", "linux",
    },
}


# -- observation seams (mockable) -----------------------------------------

def _system() -> str:
    return platform.system()


def _exists(path: str) -> bool:
    return Path(path).exists()


def _os_release() -> dict[str, str]:
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"').strip("'")
    return fields


def detect_os() -> str:
    """Return a normalized id for the running OS."""
    system = _system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"

    # Linux family: anonymity systems first, since they sit on top of Debian.
    release = _os_release()
    name = (release.get("ID", "") + " " + release.get("PRETTY_NAME", "")
            + " " + release.get("NAME", "")).lower()

    if _exists("/etc/amnesia") or release.get("ID", "").lower() == "tails" or "tails" in name:
        return "tails"
    if _exists("/usr/share/anon-gw-base-files") or _exists("/usr/share/whonix/marker/gateway"):
        return "whonix-gateway"
    if _exists("/usr/share/anon-ws-base-files") or _exists("/usr/share/whonix/marker/workstation"):
        return "whonix-workstation"
    if _exists("/etc/whonix_version") or "whonix" in name:
        return "whonix"
    if _exists("/etc/qubes-release") or _exists("/usr/share/qubes"):
        return "qubes"

    distro_id = release.get("ID", "").lower()
    if distro_id:
        return distro_id
    return "linux" if system == "Linux" else "unknown"


def os_matches(expected: str, actual: str) -> bool:
    if expected == actual:
        return True
    # "whonix" matches "whonix-workstation", etc.
    if actual.startswith(expected + "-"):
        return True
    family = OS_UMBRELLA.get(expected)
    return bool(family and actual in family)


class OsTargetProvider(Provider):
    control_id = "FLE-OS-001"

    def observe(self, ctx: ProviderContext):
        expected = ctx.config.os_policy.expected
        if not expected:
            return self.result(ctx, State.NOT_APPLICABLE, "no `os.expect` declared")
        actual = detect_os()
        observed = {"os": actual}
        if any(os_matches(e, actual) for e in expected):
            return self.result(
                ctx, State.OK, f"running {actual} (matches declared {list(expected)})",
                observed=observed,
            )
        return self.result(
            ctx, State.VIOLATION,
            f"running {actual!r}, but this posture is for {list(expected)}",
            detail="you may be doing sensitive work on the wrong operating system.",
            observed=observed,
        )


register(OsTargetProvider())
