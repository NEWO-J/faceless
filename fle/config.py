"""Load and validate the declarative desired-state config (``opsec.yaml``).

Fail-closed: a missing, malformed, or under-specified config raises
:class:`~fle.errors.ConfigError` rather than degrading to "check nothing".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .catalog import get_control
from .errors import ConfigError
from .model import Severity

DEFAULT_CONFIG_NAME = "opsec.yaml"
DEFAULT_LOCK_NAME = "opsec.lock.yaml"

_ON_COMMAND = {"block", "warn", "off"}
_AUTO_REMEDIATE = {"off", "safe", "full"}


@dataclass(frozen=True, slots=True)
class Identity:
    persona: Mapping[str, str] = field(default_factory=dict)
    real: Mapping[str, Any] = field(default_factory=dict)

    def real_values(self) -> list[str]:
        """Flatten all declared real identifiers into a comparable list."""
        out: list[str] = []
        for value in self.real.values():
            if isinstance(value, (list, tuple)):
                out.extend(str(v) for v in value)
            else:
                out.append(str(value))
        return out


@dataclass(frozen=True, slots=True)
class PostureItem:
    control_id: str
    severity: Severity
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Enforcement:
    on_command: str = "warn"
    auto_remediate: str = "safe"


@dataclass(frozen=True, slots=True)
class OpsecConfig:
    name: str
    identity: Identity
    posture: tuple[PostureItem, ...]
    enforcement: Enforcement
    source: Path | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "OpsecConfig":
        config_path = Path(path)
        try:
            raw = config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read config {config_path}: {exc}") from exc
        try:
            document = yaml.safe_load(raw) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {config_path}: {exc}") from exc
        config = cls.from_mapping(document)
        return cls(
            name=config.name,
            identity=config.identity,
            posture=config.posture,
            enforcement=config.enforcement,
            source=config_path,
        )

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> "OpsecConfig":
        if not isinstance(document, Mapping):
            raise ConfigError("config root must be a mapping")
        version = document.get("opsec_version")
        if version != 1:
            raise ConfigError(f"unsupported opsec_version {version!r}; expected 1")

        name = str(document.get("name") or "opsec")
        identity = cls._parse_identity(document.get("identity", {}))
        posture = cls._parse_posture(document.get("posture", []))
        enforcement = cls._parse_enforcement(document.get("enforcement", {}))
        return cls(name=name, identity=identity, posture=posture, enforcement=enforcement)

    # -- parsers -----------------------------------------------------------

    @staticmethod
    def _parse_identity(raw: object) -> Identity:
        if not raw:
            return Identity()
        if not isinstance(raw, Mapping):
            raise ConfigError("`identity` must be a mapping")
        persona = raw.get("persona", {}) or {}
        real = raw.get("real", {}) or {}
        if not isinstance(persona, Mapping) or not isinstance(real, Mapping):
            raise ConfigError("`identity.persona` and `identity.real` must be mappings")
        return Identity(persona={str(k): str(v) for k, v in persona.items()}, real=dict(real))

    @staticmethod
    def _parse_posture(raw: object) -> tuple[PostureItem, ...]:
        if not isinstance(raw, (list, tuple)) or not raw:
            raise ConfigError("`posture` must be a non-empty list of controls")
        items: list[PostureItem] = []
        seen: set[str] = set()
        for entry in raw:
            if not isinstance(entry, Mapping) or "control" not in entry:
                raise ConfigError("each posture item needs a `control` key")
            control_id = str(entry["control"])
            spec = get_control(control_id)  # validates existence
            if control_id in seen:
                raise ConfigError(f"duplicate control {control_id!r} in posture")
            seen.add(control_id)
            severity = spec.default_severity
            if "severity" in entry:
                try:
                    severity = Severity(str(entry["severity"]))
                except ValueError as exc:
                    raise ConfigError(
                        f"control {control_id}: bad severity {entry['severity']!r}"
                    ) from exc
            params = entry.get("params", {}) or {}
            if not isinstance(params, Mapping):
                raise ConfigError(f"control {control_id}: `params` must be a mapping")
            items.append(PostureItem(control_id=control_id, severity=severity, params=dict(params)))
        return tuple(items)

    @staticmethod
    def _parse_enforcement(raw: object) -> Enforcement:
        if not raw:
            return Enforcement()
        if not isinstance(raw, Mapping):
            raise ConfigError("`enforcement` must be a mapping")
        on_command = str(raw.get("on_command", "warn"))
        auto = str(raw.get("auto_remediate", "safe"))
        if on_command not in _ON_COMMAND:
            raise ConfigError(f"enforcement.on_command must be one of {sorted(_ON_COMMAND)}")
        if auto not in _AUTO_REMEDIATE:
            raise ConfigError(f"enforcement.auto_remediate must be one of {sorted(_AUTO_REMEDIATE)}")
        return Enforcement(on_command=on_command, auto_remediate=auto)
