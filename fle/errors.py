"""Typed errors and stable, script-friendly exit codes."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    #: Posture is non-conformant (a control >= high is in drift/violation/error).
    NON_CONFORMANT = 10
    #: The opsec.yaml config is missing, malformed, or references unknown controls.
    CONFIG_ERROR = 11
    #: A provider or engine failure unrelated to posture state itself.
    ENGINE_ERROR = 12
    USAGE_ERROR = 2


class FacelessError(Exception):
    exit_code: ExitCode = ExitCode.USAGE_ERROR


class ConfigError(FacelessError):
    exit_code = ExitCode.CONFIG_ERROR


class EngineError(FacelessError):
    exit_code = ExitCode.ENGINE_ERROR


class NotRemediable(FacelessError):
    """Raised when enforce() is called on a detect-only provider."""

    exit_code = ExitCode.ENGINE_ERROR
