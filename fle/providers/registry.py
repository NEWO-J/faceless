"""Control-ID → provider registry."""

from __future__ import annotations

from .base import Provider

_REGISTRY: dict[str, Provider] = {}


def register(provider: Provider) -> Provider:
    _REGISTRY[provider.control_id] = provider
    return provider


def get_provider(control_id: str) -> Provider | None:
    return _REGISTRY.get(control_id)


def load_builtin_providers() -> None:
    """Import built-in provider modules so they self-register (idempotent)."""
    from . import (  # noqa: F401
        browser, disk, environment, filesystem, git_identity, network,
        os_target, vpn,
    )
