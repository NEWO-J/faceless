from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from .model import PostureReport

ATTESTATION_VERSION = 1


class AttestError(Exception):
    pass


# -- key management --------------------------------------------------------

def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on env
        raise AttestError(
            "attestation needs the `cryptography` package: pip install 'faceless-engine[attest]'"
        ) from exc


def config_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home())
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "fle"


def key_path() -> Path:
    return config_dir() / "ed25519.key"


def load_or_create_key():
    """Return an Ed25519 private key, creating and persisting one if needed."""
    _require_crypto()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = key_path()
    if path.is_file():
        raw = base64.b64decode(path.read_text(encoding="utf-8").strip())
        return Ed25519PrivateKey.from_private_bytes(raw)

    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes_raw()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(raw).decode(), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def public_key_b64(private_key) -> str:
    return base64.b64encode(private_key.public_key().public_bytes_raw()).decode()


# -- baseline hashing ------------------------------------------------------

def baseline_hash_from_mapping(document: dict[str, Any]) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def baseline_hash(path: str | Path) -> str:
    """Hash the *semantic* content of a baseline config (format-insensitive)."""
    try:
        document = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise AttestError(f"cannot hash baseline {path}: {exc}") from exc
    return baseline_hash_from_mapping(document)


# -- produce ---------------------------------------------------------------

def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def produce(
    report: PostureReport,
    *,
    baseline_hash: str,
    baseline_name: str,
    private_key,
    nonce: str = "",
    subject: str = "",
) -> dict[str, Any]:
    """Build a signed attestation token from a posture report."""
    payload: dict[str, Any] = {
        "attestation_version": ATTESTATION_VERSION,
        "baseline_hash": baseline_hash,
        "baseline_name": baseline_name,
        "conformant": report.conformant,
        # per-control state only; never the observed evidence
        "results": [{"control": r.control_id, "state": r.state.value} for r in report.results],
        "issued_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "nonce": nonce,
        "subject": subject,
        "public_key": public_key_b64(private_key),
    }
    signature = private_key.sign(_canonical(payload))
    payload["signature"] = base64.b64encode(signature).decode()
    return payload


# -- verify ----------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    reasons: tuple[str, ...]
    subject: str = ""
    public_key: str = ""

    @property
    def summary(self) -> str:
        return "ACCEPTED" if self.ok else "REJECTED: " + "; ".join(self.reasons)


def _parse_iso(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, TypeError):
        return None


def verify(
    token: dict[str, Any],
    *,
    required_baseline_hash: str | None = None,
    max_age_seconds: float | None = 900.0,
    expected_nonce: str | None = None,
    allowed_public_keys: Iterable[str] | None = None,
) -> VerifyResult:
    """Check a token's signature, conformance, baseline, freshness, and identity."""
    _require_crypto()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    reasons: list[str] = []
    pub_b64 = str(token.get("public_key", ""))
    subject = str(token.get("subject", ""))

    # 1. signature over the canonical payload (minus the signature field)
    signature_b64 = token.get("signature")
    if not signature_b64 or not pub_b64:
        return VerifyResult(False, ("missing signature or public key",), subject, pub_b64)
    payload = {k: v for k, v in token.items() if k != "signature"}
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(base64.b64decode(signature_b64), _canonical(payload))
    except (InvalidSignature, ValueError, TypeError):
        reasons.append("invalid signature")

    # 2. conformance
    if not token.get("conformant", False):
        reasons.append("posture is non-conformant")

    # 3. baseline binding: attested against the required config, not a weaker one
    if required_baseline_hash is not None and token.get("baseline_hash") != required_baseline_hash:
        reasons.append("baseline hash does not match the required config")

    # 4. freshness
    if max_age_seconds is not None:
        issued = _parse_iso(str(token.get("issued_at", "")))
        if issued is None:
            reasons.append("missing or invalid issued_at")
        elif time.time() - issued > max_age_seconds:
            reasons.append(f"attestation is stale (older than {int(max_age_seconds)}s)")

    # 5. replay protection
    if expected_nonce is not None and token.get("nonce") != expected_nonce:
        reasons.append("nonce mismatch (possible replay)")

    # 6. membership
    if allowed_public_keys is not None and pub_b64 not in set(allowed_public_keys):
        reasons.append("public key is not on the allowlist")

    return VerifyResult(not reasons, tuple(reasons), subject, pub_b64)


def load_token(source: str | Path) -> dict[str, Any]:
    text = sys.stdin.read() if str(source) == "-" else Path(source).read_text(encoding="utf-8")
    try:
        token = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AttestError(f"not a valid attestation token: {exc}") from exc
    if not isinstance(token, dict):
        raise AttestError("attestation token must be a JSON object")
    return token
