"""Shell-hook rendering and idempotent install/uninstall."""

from __future__ import annotations

import pytest

from fle import hooks


def test_render_powershell_has_markers_and_status_call():
    block = hooks.render("powershell", on_command="warn", invocation="fle")
    assert hooks.MARKER_BEGIN in block and hooks.MARKER_END in block
    assert "fle status --fast" in block
    assert "PSReadLine" not in block  # only in block mode


def test_render_powershell_block_mode_adds_gate():
    block = hooks.render("powershell", on_command="block", invocation="fle")
    assert "PSReadLine" in block
    assert "verify --fast" in block


def test_render_bash_and_zsh_differ():
    bash = hooks.render("bash", invocation="fle")
    zsh = hooks.render("zsh", invocation="fle")
    assert "PROMPT_COMMAND" in bash
    assert "precmd_functions" in zsh


def test_unsupported_shell_raises():
    with pytest.raises(ValueError):
        hooks.render("fish")


def test_install_is_idempotent(tmp_path):
    profile = tmp_path / "profile.ps1"
    profile.write_text("# my stuff\nSet-Alias ll ls\n", encoding="utf-8")
    hooks.install("powershell", profile, invocation="fle")
    hooks.install("powershell", profile, invocation="fle")  # twice
    content = profile.read_text(encoding="utf-8")
    assert content.count(hooks.MARKER_BEGIN) == 1
    assert "# my stuff" in content  # preserved user content


def test_uninstall_removes_block_only(tmp_path):
    profile = tmp_path / "profile.ps1"
    profile.write_text("# keep me\n", encoding="utf-8")
    hooks.install("powershell", profile, invocation="fle")
    assert hooks.uninstall(profile) is True
    content = profile.read_text(encoding="utf-8")
    assert hooks.MARKER_BEGIN not in content
    assert "# keep me" in content
    assert hooks.uninstall(profile) is False  # nothing left to remove
