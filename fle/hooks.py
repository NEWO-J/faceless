"""Per-command shell hooks — run a fast posture check at every prompt.

This is the load-bearing anti-drift mechanism: if the human has to *remember* to
run ``fle verify``, the drift problem is unsolved. The hook wires a fast check
into the shell so posture is re-asserted automatically. Blocking is best-effort
per shell and documented as such.

Everything renders to a string first (so it can be snapshot-tested) and is
spliced into the profile between stable markers, making install/uninstall
idempotent.
"""

from __future__ import annotations

from pathlib import Path

MARKER_BEGIN = "# >>> fle opsec hook >>>"
MARKER_END = "# <<< fle opsec hook <<<"

SUPPORTED_SHELLS = ("powershell", "bash", "zsh")


def _powershell_block(on_command: str, invocation: str) -> str:
    block = f"""{MARKER_BEGIN}
function global:prompt {{
    $__fle = (& {invocation} status --fast 2>$null)
    if ($LASTEXITCODE -ne 0) {{ $__c = 'Red' }} else {{ $__c = 'Green' }}
    Write-Host "[$__fle]" -ForegroundColor $__c -NoNewline
    return " PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "
}}"""
    if on_command == "block":
        block += f"""
if (Get-Module -ListAvailable -Name PSReadLine) {{
    Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {{
        & {invocation} verify --fast --quiet 2>$null | Out-Null
        if ($LASTEXITCODE -eq 10) {{
            Write-Host "`n[fle] posture non-conformant — command blocked. Run '{invocation} verify'." -ForegroundColor Red
        }} else {{
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        }}
    }}
}}"""
    return block + f"\n{MARKER_END}\n"


def _posix_block(shell: str, on_command: str, invocation: str) -> str:
    hook = f"""{MARKER_BEGIN}
__fle_saved_ps1="${{__fle_saved_ps1:-$PS1}}"
__fle_prompt() {{
    __fle_status="$({invocation} status --fast 2>/dev/null)"
    PS1="[${{__fle_status}}] ${{__fle_saved_ps1}}"
}}"""
    if shell == "zsh":
        hook += "\nprecmd_functions+=(__fle_prompt)"
    else:  # bash
        hook += '\nPROMPT_COMMAND="__fle_prompt${PROMPT_COMMAND:+; $PROMPT_COMMAND}"'
    if on_command == "block":
        hook += f"""
__fle_preexec() {{
    {invocation} verify --fast --quiet >/dev/null 2>&1 || \\
        echo "[fle] posture non-conformant — run '{invocation} verify'." >&2
}}"""
    return hook + f"\n{MARKER_END}\n"


def render(shell: str, on_command: str = "warn", invocation: str = "fle") -> str:
    """Return the hook block for a shell (does not touch the filesystem)."""
    if shell == "powershell":
        return _powershell_block(on_command, invocation)
    if shell in ("bash", "zsh"):
        return _posix_block(shell, on_command, invocation)
    raise ValueError(f"unsupported shell {shell!r}; supported: {SUPPORTED_SHELLS}")


def _strip_existing(content: str) -> str:
    """Remove any previously-installed fle block, preserving the rest."""
    if MARKER_BEGIN not in content:
        return content
    lines = content.splitlines(keepends=True)
    out, skipping = [], False
    for line in lines:
        if line.strip() == MARKER_BEGIN:
            skipping = True
            continue
        if line.strip() == MARKER_END:
            skipping = False
            continue
        if not skipping:
            out.append(line)
    return "".join(out)


def install(shell: str, profile_path: str | Path, *, on_command: str = "warn", invocation: str = "fle") -> Path:
    """Idempotently splice the hook into the profile; returns the path."""
    path = Path(profile_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    cleaned = _strip_existing(existing).rstrip("\n")
    block = render(shell, on_command=on_command, invocation=invocation)
    joined = (cleaned + "\n\n" if cleaned else "") + block
    path.write_text(joined, encoding="utf-8")
    return path


def uninstall(profile_path: str | Path) -> bool:
    """Remove the fle block if present. Returns True if something was removed."""
    path = Path(profile_path)
    if not path.is_file():
        return False
    existing = path.read_text(encoding="utf-8")
    if MARKER_BEGIN not in existing:
        return False
    path.write_text(_strip_existing(existing).rstrip("\n") + "\n", encoding="utf-8")
    return True
