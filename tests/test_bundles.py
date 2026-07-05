"""Bundle expansion in the config."""

from __future__ import annotations

import pytest

from fle.catalog import BUNDLES, get_bundle
from fle.config import OpsecConfig
from fle.errors import ConfigError


def test_bundle_expands_to_controls():
    cfg = OpsecConfig.from_mapping({
        "opsec_version": 1, "name": "t",
        "posture": [{"bundle": "linux-net"}],
    })
    ids = [i.control_id for i in cfg.posture]
    assert ids == get_bundle("linux-net")
    assert "OPSEC-NET-003" in ids


def test_bundle_and_explicit_control_dedupe():
    cfg = OpsecConfig.from_mapping({
        "opsec_version": 1, "name": "t",
        # explicit-with-params first so it wins over the bundle's default
        "posture": [
            {"control": "OPSEC-EGRESS-002", "params": {"interface": "wg0"}},
            {"bundle": "linux-net"},
        ],
    })
    egress = [i for i in cfg.posture if i.control_id == "OPSEC-EGRESS-002"]
    assert len(egress) == 1
    assert egress[0].params == {"interface": "wg0"}


def test_unknown_bundle_rejected():
    with pytest.raises(ConfigError):
        OpsecConfig.from_mapping({
            "opsec_version": 1, "name": "t",
            "posture": [{"bundle": "linux-nope"}],
        })


def test_every_bundled_control_exists():
    from fle.catalog import CATALOG

    for controls in BUNDLES.values():
        for control_id in controls:
            assert control_id in CATALOG
