"""Built-in providers for the OpSec-as-Code control catalog."""

from __future__ import annotations

from .base import Provider, ProviderContext
from .registry import get_provider, load_builtin_providers, register

__all__ = [
    "Provider",
    "ProviderContext",
    "get_provider",
    "load_builtin_providers",
    "register",
]
