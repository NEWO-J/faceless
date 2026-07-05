"""Attestation: sign, verify, and reject tampered / stale / wrong-baseline tokens."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fle import attest
from fle.model import CheckResult, PostureReport, Severity, State


def _report(conformant=True):
    state = State.OK if conformant else State.VIOLATION
    return PostureReport(results=(
        CheckResult("FLE-NET-003", state, Severity.HIGH, "firewall"),
        CheckResult("FLE-DISK-001", State.OK, Severity.HIGH, "disk", observed={"secret": "x"}),
    ))


def _token(report=None, key=None, nonce="", baseline_hash="abc123", name="room"):
    key = key or Ed25519PrivateKey.generate()
    return attest.produce(report or _report(), baseline_hash=baseline_hash,
                          baseline_name=name, private_key=key, nonce=nonce)


def test_roundtrip_accepts():
    token = _token()
    result = attest.verify(token, required_baseline_hash="abc123", max_age_seconds=60)
    assert result.ok, result.reasons


def test_token_never_leaks_observed_values():
    token = _token()
    assert "secret" not in str(token)  # observed evidence must not be in the token
    assert all(set(r) == {"control", "state"} for r in token["results"])


def test_tampered_conformant_flag_is_rejected():
    token = _token()
    token["conformant"] = True
    token["results"][0]["state"] = "ok"  # flip a fail to a pass after signing
    # (token was already conformant; instead tamper a real one:)
    bad = _token(report=_report(conformant=False))
    bad["conformant"] = True
    result = attest.verify(bad, max_age_seconds=60)
    assert not result.ok
    assert "invalid signature" in result.reasons


def test_non_conformant_is_rejected():
    token = _token(report=_report(conformant=False))
    result = attest.verify(token, max_age_seconds=60)
    assert not result.ok
    assert "posture is non-conformant" in result.reasons


def test_wrong_baseline_is_rejected():
    token = _token(baseline_hash="weakconfig")
    result = attest.verify(token, required_baseline_hash="the-strong-one")
    assert not result.ok
    assert any("baseline" in r for r in result.reasons)


def test_stale_token_is_rejected():
    token = _token()
    token["issued_at"] = "2000-01-01T00:00:00+00:00"  # ancient; breaks signature too
    # Re-sign an old timestamp to isolate the freshness check:
    key = Ed25519PrivateKey.generate()
    payload = attest.produce(_report(), baseline_hash="abc123", baseline_name="r", private_key=key)
    payload.pop("signature")
    payload["issued_at"] = "2000-01-01T00:00:00+00:00"
    sig = key.sign(attest._canonical(payload))
    import base64
    payload["signature"] = base64.b64encode(sig).decode()
    result = attest.verify(payload, max_age_seconds=900)
    assert not result.ok
    assert any("stale" in r for r in result.reasons)


def test_nonce_mismatch_is_rejected():
    token = _token(nonce="server-nonce-A")
    result = attest.verify(token, expected_nonce="server-nonce-B", max_age_seconds=60)
    assert not result.ok
    assert any("nonce" in r for r in result.reasons)


def test_allowlist_enforced():
    key = Ed25519PrivateKey.generate()
    token = _token(key=key)
    good = attest.public_key_b64(key)
    assert attest.verify(token, allowed_public_keys=[good], max_age_seconds=60).ok
    assert not attest.verify(token, allowed_public_keys=["someone-else"], max_age_seconds=60).ok


def test_baseline_hash_is_format_insensitive():
    a = attest.baseline_hash_from_mapping({"opsec_version": 1, "posture": [{"control": "X"}]})
    b = attest.baseline_hash_from_mapping({"posture": [{"control": "X"}], "opsec_version": 1})
    assert a == b
