"""Faceless Engine (``fle``) — an OpSec-as-Code posture engine.

Declare your operational-security posture as code (``opsec.yaml``) and re-assert
it on every command so it can never silently drift. The flow is IaC-shaped:

    declare (opsec.yaml)  ->  verify (drift check)  ->  apply (converge)  ->  lock

Each declared **control** has a stable catalog ID (``FLE-<DOMAIN>-<NNN>``) and
is backed by a **provider** that observes actual system state. The engine emits a
:class:`~fle.model.PostureReport`; a shell hook runs a fast verify at every prompt
so the human never has to remember to check.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.2.0"
