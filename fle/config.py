"""Load and validate the declarative desired-state config (``opsec.yaml``).

Fail-closed: a missing, malformed, or under-specified config raises
:class:`~fle.errors.ConfigError` rather than degrading to "check nothing".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .catalog import CATALOG, ControlSpec, get_bundle, get_control
from .errors import ConfigError
from .model import Severity

DEFAULT_CONFIG_NAME = "opsec.yaml"
DEFAULT_LOCK_NAME = "opsec.lock.yaml"

_ON_COMMAND = {"block", "warn", "off"}
_AUTO_REMEDIATE = {"off", "safe", "full"}

_CUSTOM_ID_RE = re.compile(r"^FLE-[A-Z0-9]+-[0-9]+$")
_CUSTOM_KINDS = {"command", "file", "env", "sysctl"}


def _custom_spec(cid: str, kind: str, entry: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and extract the kind-specific fields for a custom control."""
    if kind == "command":
        run = entry.get("run")
        if not isinstance(run, (list, tuple)) or not run:
            raise ConfigError(f"{cid}: a `command` control needs a non-empty `run` list")
        return {"run": list(run), "timeout": entry.get("timeout", 20)}
    if kind == "file":
        if not entry.get("path"):
            raise ConfigError(f"{cid}: a `file` control needs a `path`")
        return {"path": str(entry["path"])}
    if kind == "env":
        if not entry.get("var"):
            raise ConfigError(f"{cid}: an `env` control needs a `var`")
        return {"var": str(entry["var"])}
    if kind == "sysctl":
        if not entry.get("key"):
            raise ConfigError(f"{cid}: a `sysctl` control needs a `key`")
        return {"key": str(entry["key"])}
    raise ConfigError(f"{cid}: unsupported kind {kind!r}")


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
class OsPolicy:
    """Declared target operating system(s) for this posture."""

    expected: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CustomControl:
    """A user-defined control declared in YAML (no Python)."""

    id: str
    title: str
    kind: str
    severity: Severity
    domain: str = "custom"
    rationale: str = ""
    spec: Mapping[str, Any] = field(default_factory=dict)
    assertion: Mapping[str, Any] = field(default_factory=dict)

    def control_spec(self) -> ControlSpec:
        return ControlSpec(
            id=self.id, domain=self.domain, title=self.title,
            default_severity=self.severity, remediable=False, rationale=self.rationale,
        )


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
    os_policy: OsPolicy = field(default_factory=OsPolicy)
    custom_controls: Mapping[str, CustomControl] = field(default_factory=dict)
    source: Path | None = None

    def spec_for(self, control_id: str) -> ControlSpec:
        """Resolve a control's spec from custom definitions or the built-in catalog."""
        custom = self.custom_controls.get(control_id)
        if custom is not None:
            return custom.control_spec()
        return get_control(control_id)

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
            os_policy=config.os_policy,
            custom_controls=config.custom_controls,
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
        custom = cls._parse_custom_controls(document.get("controls", []))
        posture = cls._parse_posture(document.get("posture", []), custom)
        enforcement = cls._parse_enforcement(document.get("enforcement", {}))
        os_policy = cls._parse_os(document.get("os", {}))
        return cls(name=name, identity=identity, posture=posture,
                   enforcement=enforcement, os_policy=os_policy, custom_controls=custom)

    @staticmethod
    def _parse_custom_controls(raw: object) -> dict[str, CustomControl]:
        if not raw:
            return {}
        if not isinstance(raw, (list, tuple)):
            raise ConfigError("`controls` must be a list of custom control definitions")
        out: dict[str, CustomControl] = {}
        for entry in raw:
            if not isinstance(entry, Mapping):
                raise ConfigError("each custom control must be a mapping")
            cid = str(entry.get("id", "")).strip()
            if not _CUSTOM_ID_RE.match(cid):
                raise ConfigError(f"custom control id {cid!r} must match FLE-<DOMAIN>-<NNN>")
            if cid in CATALOG:
                raise ConfigError(f"custom control {cid} collides with a built-in control")
            if cid in out:
                raise ConfigError(f"duplicate custom control {cid}")
            kind = str(entry.get("kind", "")).strip()
            if kind not in _CUSTOM_KINDS:
                raise ConfigError(f"{cid}: kind must be one of {sorted(_CUSTOM_KINDS)}")
            assertion = entry.get("assert", {})
            if not isinstance(assertion, Mapping) or not assertion:
                raise ConfigError(f"{cid}: `assert` must be a non-empty mapping")
            try:
                severity = Severity(str(entry.get("severity", "medium")))
            except ValueError as exc:
                raise ConfigError(f"{cid}: bad severity {entry.get('severity')!r}") from exc
            spec = _custom_spec(cid, kind, entry)
            out[cid] = CustomControl(
                id=cid, title=str(entry.get("title") or cid), kind=kind, severity=severity,
                domain=str(entry.get("domain", "custom")).lower(),
                rationale=str(entry.get("rationale", "")), spec=spec, assertion=dict(assertion),
            )
        return out

    # -- parsers -----------------------------------------------------------

    @staticmethod
    def _parse_os(raw: object) -> OsPolicy:
        if not raw:
            return OsPolicy()
        if not isinstance(raw, Mapping):
            raise ConfigError("`os` must be a mapping")
        expect = raw.get("expect", [])
        if isinstance(expect, str):
            expected = (expect.strip().lower(),)
        elif isinstance(expect, (list, tuple)):
            expected = tuple(str(e).strip().lower() for e in expect if str(e).strip())
        else:
            raise ConfigError("`os.expect` must be a string or a list of strings")
        return OsPolicy(expected=expected)

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
    def _parse_posture(
        raw: object, custom: Mapping[str, "CustomControl"] | None = None
    ) -> tuple[PostureItem, ...]:
        custom = custom or {}
        if not isinstance(raw, (list, tuple)) or not raw:
            raise ConfigError("`posture` must be a non-empty list of controls")
        items: list[PostureItem] = []
        seen: set[str] = set()

        def default_severity(control_id: str) -> Severity:
            if control_id in custom:
                return custom[control_id].severity
            return get_control(control_id).default_severity  # validates existence

        for entry in raw:
            if not isinstance(entry, Mapping):
                raise ConfigError("each posture item must be a mapping")

            # A bundle expands to its controls with default severity / no params.
            if "bundle" in entry:
                for control_id in get_bundle(str(entry["bundle"])):
                    if control_id in seen:
                        continue
                    seen.add(control_id)
                    items.append(PostureItem(
                        control_id=control_id,
                        severity=default_severity(control_id),
                        params={},
                    ))
                continue

            if "control" not in entry:
                raise ConfigError("each posture item needs a `control` or `bundle` key")
            control_id = str(entry["control"])
            severity = default_severity(control_id)  # validates builtin/custom existence
            if control_id in seen:
                raise ConfigError(f"duplicate control {control_id!r} in posture")
            seen.add(control_id)
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
        # YAML 1.1 turns bare off/on/no/yes into booleans; map them back so
        # `auto_remediate: off` behaves as the user obviously intended.
        bool_words = {True: "on", False: "off"}
        on_command = str(bool_words.get(raw.get("on_command"), raw.get("on_command", "warn")))
        auto = str(bool_words.get(raw.get("auto_remediate"), raw.get("auto_remediate", "safe")))
        if on_command not in _ON_COMMAND:
            raise ConfigError(f"enforcement.on_command must be one of {sorted(_ON_COMMAND)}")
        if auto not in _AUTO_REMEDIATE:
            raise ConfigError(f"enforcement.auto_remediate must be one of {sorted(_AUTO_REMEDIATE)}")
        return Enforcement(on_command=on_command, auto_remediate=auto)
