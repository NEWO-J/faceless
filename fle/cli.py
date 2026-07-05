"""Command-line front-end for the OpSec-as-Code posture engine.

    fle init                     write an opsec.yaml (guided)
    fle verify | plan            evaluate posture (drift check); read-only
    fle apply                    converge failing, remediable controls
    fle lock                     pin the current known-good posture
    fle status                   one-line summary (for the shell prompt)
    fle hook install|uninstall   wire the per-command shell hook

Nothing here is a gate that runs code — it evaluates *posture*. Exit codes:
0 conformant, 10 non-conformant, 11 config error, 12 engine error, 2 usage.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from rich.panel import Panel
from rich.text import Text

from . import __version__, attest, cache, hooks
from .attest import AttestError
from .config import DEFAULT_CONFIG_NAME, DEFAULT_LOCK_NAME, OpsecConfig
from .engine import converge, evaluate
from .errors import ExitCode, FacelessError
from .lockfile import read_lock, write_lock
from .model import PostureReport
from .report import (
    console,
    render_detail,
    render_enforcement,
    render_report,
    status_line,
    to_json,
    to_sarif,
)

_FAST_TTL_SECONDS = 300.0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fle", description="OpSec-as-Code posture engine.")
    parser.add_argument("--version", action="version", version=f"fle {__version__}")

    cfg = argparse.ArgumentParser(add_help=False)
    cfg.add_argument("-c", "--config", default=None,
                     help=f"path to the config (default: ./{DEFAULT_CONFIG_NAME})")

    sub = parser.add_subparsers(dest="subcommand", required=False)

    p_init = sub.add_parser("init", help="write an opsec.yaml (guided)")
    p_init.add_argument("-c", "--config", default=None)
    p_init.add_argument("--force", action="store_true", help="overwrite an existing config")
    p_init.set_defaults(func=cmd_init)

    p_verify = sub.add_parser("verify", aliases=["plan"], parents=[cfg],
                              help="evaluate posture (drift check)")
    p_verify.add_argument("--fast", action="store_true", help="use cached results for expensive checks")
    p_verify.add_argument("--json", action="store_true", help="emit the report as JSON")
    p_verify.add_argument("--sarif", action="store_true", help="emit the report as SARIF")
    p_verify.add_argument("--quiet", action="store_true", help="no human output; exit code only")
    p_verify.add_argument("--no-lock", action="store_true", help="ignore opsec.lock.yaml")
    p_verify.set_defaults(func=cmd_verify)

    p_apply = sub.add_parser("apply", parents=[cfg], help="converge failing, remediable controls")
    p_apply.add_argument("--full", action="store_true", help="include destructive remediations")
    p_apply.set_defaults(func=cmd_apply)

    p_lock = sub.add_parser("lock", parents=[cfg], help="pin the current known-good posture")
    p_lock.set_defaults(func=cmd_lock)

    p_status = sub.add_parser("status", parents=[cfg], help="one-line posture summary")
    p_status.add_argument("--fast", action="store_true", default=True)
    p_status.set_defaults(func=cmd_status)

    p_hook = sub.add_parser("hook", help="wire the per-command shell hook")
    hook_sub = p_hook.add_subparsers(dest="hook_action", required=True)
    h_install = hook_sub.add_parser("install", parents=[cfg])
    h_install.add_argument("--shell", default=_default_shell(), choices=hooks.SUPPORTED_SHELLS)
    h_install.add_argument("--profile", default=None, help="profile path (auto-detected if omitted)")
    h_install.set_defaults(func=cmd_hook_install)
    h_uninstall = hook_sub.add_parser("uninstall")
    h_uninstall.add_argument("--shell", default=_default_shell(), choices=hooks.SUPPORTED_SHELLS)
    h_uninstall.add_argument("--profile", default=None)
    h_uninstall.set_defaults(func=cmd_hook_uninstall)

    p_key = sub.add_parser("key", help="show your attestation public key (creates one if needed)")
    p_key.set_defaults(func=cmd_key)

    p_attest = sub.add_parser("attest", parents=[cfg],
                              help="sign a posture attestation against a required baseline")
    p_attest.add_argument("--nonce", default="", help="challenge string from the gatekeeper")
    p_attest.add_argument("--subject", default="", help="who you are in the room (e.g. persona handle)")
    p_attest.add_argument("-o", "--out", default=None, help="write the token here (default: stdout)")
    p_attest.set_defaults(func=cmd_attest)

    p_va = sub.add_parser("verify-attestation", help="verify someone's attestation token")
    p_va.add_argument("token", help="path to the token JSON, or - for stdin")
    p_va.add_argument("--baseline", default=None, help="required baseline config to bind against")
    p_va.add_argument("--max-age", type=float, default=900.0, help="max token age in seconds")
    p_va.add_argument("--nonce", default=None, help="challenge the token must echo")
    p_va.add_argument("--allow", action="append", default=None, metavar="PUBKEY",
                      help="allowlisted public key (repeatable)")
    p_va.set_defaults(func=cmd_verify_attestation)

    return parser


# -- helpers ---------------------------------------------------------------


def _config_path(namespace: argparse.Namespace) -> Path:
    return Path(getattr(namespace, "config", None) or DEFAULT_CONFIG_NAME)


def _lock_path(config_path: Path) -> Path:
    return config_path.parent / DEFAULT_LOCK_NAME


def _load(namespace: argparse.Namespace) -> OpsecConfig:
    path = _config_path(namespace)
    if not path.exists():
        raise FacelessError(f"no {path} found — run `fle init` to create one")
    return OpsecConfig.from_file(path)


def _default_shell() -> str:
    return "powershell" if sys.platform == "win32" else "bash"


def _default_invocation() -> str:
    return "fle" if shutil.which("fle") else "python -m fle"


def _powershell_profile_path() -> Path:
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "$PROFILE"],
            capture_output=True, text=True, timeout=15, check=False,
        ).stdout.strip()
        if out:
            return Path(out)
    except (OSError, subprocess.SubprocessError):
        pass
    return Path.home() / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1"


def _profile_path_for(shell: str, override: str | None) -> Path:
    if override:
        return Path(override)
    if shell == "powershell":
        return _powershell_profile_path()
    return Path.home() / (".zshrc" if shell == "zsh" else ".bashrc")


# -- subcommands -----------------------------------------------------------


def cmd_verify(namespace: argparse.Namespace) -> int:
    config = _load(namespace)
    cfg_path = _config_path(namespace)
    lock = None if namespace.no_lock else read_lock(_lock_path(cfg_path))
    cache_path = cache.default_cache_path(cfg_path)
    cached = cache.load(cache_path, _FAST_TTL_SECONDS) if namespace.fast else None

    report = evaluate(config, fast=namespace.fast, lock=lock, cache=cached)
    if not namespace.fast:
        cache.save(report.results, cache_path)  # refresh the fast-path cache

    if namespace.json:
        print(to_json(report, name=config.name))
    elif namespace.sarif:
        print(to_sarif(report, name=config.name))
    elif not namespace.quiet:
        render_report(report, name=config.name)
        render_detail(report.results)
    return report.exit_code()


def cmd_apply(namespace: argparse.Namespace) -> int:
    config = _load(namespace)
    report = evaluate(config)
    render_report(report, name=config.name)
    outcomes = converge(config, report, full=namespace.full)
    console.print("[bold]Remediation:[/]")
    render_enforcement(outcomes)
    # Re-verify to show the converged state and set the exit code.
    after = evaluate(config)
    render_report(after, name=config.name)
    return after.exit_code()


def cmd_lock(namespace: argparse.Namespace) -> int:
    config = _load(namespace)
    cfg_path = _config_path(namespace)
    report = evaluate(config)
    if not report.conformant:
        render_report(report, name=config.name)
        console.print("[yellow]Refusing to lock a non-conformant posture.[/] Fix drift, then `fle lock`.")
        return report.exit_code()
    snapshot = write_lock(report, _lock_path(cfg_path))
    console.print(f"[green]Locked {len(snapshot)} control(s)[/] to {_lock_path(cfg_path).name}.")
    return ExitCode.OK


def cmd_status(namespace: argparse.Namespace) -> int:
    config = _load(namespace)
    cfg_path = _config_path(namespace)
    lock = read_lock(_lock_path(cfg_path))
    cached = cache.load(cache.default_cache_path(cfg_path), _FAST_TTL_SECONDS)
    report = evaluate(config, fast=True, lock=lock, cache=cached)
    print(status_line(report))  # stdout: consumed by the prompt
    return report.exit_code()


def cmd_hook_install(namespace: argparse.Namespace) -> int:
    path = _profile_path_for(namespace.shell, namespace.profile)
    # Read on_command from config if present, else default to warn.
    on_command = "warn"
    cfg_path = _config_path(namespace)
    if cfg_path.exists():
        on_command = OpsecConfig.from_file(cfg_path).enforcement.on_command
    written = hooks.install(namespace.shell, path, on_command=on_command,
                            invocation=_default_invocation())
    console.print(Panel(
        Text.assemble(
            (f"Installed the {namespace.shell} hook into {written}\n", "bold green"),
            (f"Mode: on_command={on_command}. Open a new shell to activate.\n", "dim"),
            ("Undo with: fle hook uninstall", "cyan"),
        ),
        title="[bold green]FLE · HOOK INSTALLED[/]", border_style="green", expand=False,
    ))
    return ExitCode.OK


def cmd_hook_uninstall(namespace: argparse.Namespace) -> int:
    path = _profile_path_for(namespace.shell, namespace.profile)
    removed = hooks.uninstall(path)
    if removed:
        console.print(f"[green]Removed the fle hook[/] from {path}.")
    else:
        console.print(f"[dim]No fle hook found in {path}.[/]")
    return ExitCode.OK


def cmd_init(namespace: argparse.Namespace) -> int:
    path = Path(getattr(namespace, "config", None) or DEFAULT_CONFIG_NAME)
    if path.exists() and not namespace.force:
        console.print(f"[yellow]{path} exists.[/] Re-run with --force to overwrite.")
        return ExitCode.OK

    interactive = sys.stdin.isatty()

    def ask(q: str, default: str = "") -> str:
        if not interactive:
            return default
        try:
            return input(f"{q}{f' [{default}]' if default else ''}: ").strip() or default
        except (EOFError, KeyboardInterrupt):
            return default

    name = ask("Config name", "my-posture")
    git_name = ask("Persona git name", "ghostwriter")
    git_email = ask("Persona git email", "ghost@pseudonymous.example")
    real_name = ask("Your REAL name (to guard against, optional)")
    real_email = ask("Your REAL email (to guard against, optional)")
    interface = ask("VPN interface to require (blank to skip)", "")

    path.write_text(_render_config(name, git_name, git_email, real_name, real_email, interface),
                    encoding="utf-8")
    console.print(Panel(
        Text.assemble(
            (f"Wrote {path}.\n\n", "bold green"),
            ("Next:\n", "bold"),
            ("  fle verify            check your posture now\n", "cyan"),
            ("  fle lock              pin it once it's clean\n", "cyan"),
            ("  fle hook install      re-check on every command\n", "cyan"),
        ),
        title="[bold green]FLE · READY[/]", border_style="green", expand=False,
    ))
    return ExitCode.OK


def _render_config(name, git_name, git_email, real_name, real_email, interface) -> str:
    real_names = f'["{real_name}"]' if real_name else "[]"
    real_emails = f'["{real_email}"]' if real_email else "[]"
    egress = (
        f"\n  - control: FLE-EGRESS-001\n    params: {{ interface: {interface} }}"
        if interface else ""
    )
    return f"""# OpSec-as-Code posture — generated by `fle init`.
opsec_version: 1
name: {name}

identity:
  persona:
    git_name: {git_name}
    git_email: {git_email}
  real:
    names: {real_names}
    emails: {real_emails}

posture:
  - control: FLE-IDENTITY-101          # git identity == persona, != real
  - control: FLE-SECRET-050            # no secrets in the environment
  - control: FLE-SECRET-060            # forbidden plaintext secret files absent
    params: {{ forbidden_paths: ["~/.aws/credentials", "~/.netrc"] }}{egress}
  - control: FLE-DISK-001              # system volume encryption on

enforcement:
  on_command: warn        # block | warn | off
  auto_remediate: safe    # off | safe | full
"""


def cmd_key(namespace: argparse.Namespace) -> int:
    key = attest.load_or_create_key()
    pub = attest.public_key_b64(key)
    console.print(Panel(
        Text.assemble(("Your attestation public key (share this with room admins):\n\n", "bold"),
                      (pub, "cyan")),
        title="[bold]FLE · ATTESTATION KEY[/]", border_style="cyan", expand=False,
    ))
    print(pub)  # stdout, so it can be piped
    return ExitCode.OK


def cmd_attest(namespace: argparse.Namespace) -> int:
    config = _load(namespace)
    cfg_path = _config_path(namespace)
    report = evaluate(config)
    key = attest.load_or_create_key()
    token = attest.produce(
        report,
        baseline_hash=attest.baseline_hash(cfg_path),
        baseline_name=config.name,
        private_key=key,
        nonce=namespace.nonce,
        subject=namespace.subject,
    )
    payload = json.dumps(token, indent=2)
    if namespace.out:
        Path(namespace.out).write_text(payload, encoding="utf-8")
        console.print(f"[green]Wrote attestation to {namespace.out}[/]")
    else:
        print(payload)
    if not report.conformant:
        console.print("[yellow]Warning: your posture is non-conformant; a gatekeeper will reject this.[/]")
    return report.exit_code()


def cmd_verify_attestation(namespace: argparse.Namespace) -> int:
    token = attest.load_token(namespace.token)
    required = attest.baseline_hash(namespace.baseline) if namespace.baseline else None
    result = attest.verify(
        token,
        required_baseline_hash=required,
        max_age_seconds=namespace.max_age,
        expected_nonce=namespace.nonce,
        allowed_public_keys=namespace.allow,
    )
    border = "green" if result.ok else "red"
    who = result.subject or "(no subject)"
    console.print(Panel(
        Text.assemble(
            (f"{result.summary}\n", "bold green" if result.ok else "bold red"),
            (f"subject: {who}\n", "dim"),
            (f"key: {result.public_key[:16]}...", "dim"),
        ),
        title="[bold]FLE · ATTESTATION[/]", border_style=border, expand=False,
    ))
    return ExitCode.OK if result.ok else ExitCode.NON_CONFORMANT


def print_quickstart() -> None:
    console.print(Panel(
        Text.assemble(
            ("fle — declare your opsec posture as code; re-check it every command.\n\n", "bold"),
            ("  fle init          write opsec.yaml\n", "cyan"),
            ("  fle verify        check for posture drift\n", "cyan"),
            ("  fle apply         fix what can be fixed\n", "cyan"),
            ("  fle lock          pin known-good state\n", "cyan"),
            ("  fle hook install  re-check on every command\n", "cyan"),
        ),
        title="[bold cyan]fle[/]", border_style="cyan", expand=False,
    ))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    namespace = parser.parse_args(argv)
    if getattr(namespace, "func", None) is None:
        print_quickstart()
        return int(ExitCode.OK)
    try:
        return int(namespace.func(namespace))
    except AttestError as exc:
        console.print(f"[bold red]fle: {exc}[/]")
        return int(ExitCode.ENGINE_ERROR)
    except FacelessError as exc:
        console.print(f"[bold red]fle: {exc}[/]")
        return int(exc.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
