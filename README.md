# faceless engine: OpSec-as-Code

> Declare your operational-security posture as code, then re-assert it on every
> command so it can never silently drift.

Humans are the weak point of operational security. You set up your posture once,
then get tired and forget a piece of it. `fle` moves the point of failure from
runtime to configuration: you write down the posture you want in `opsec.yaml`,
and the engine checks reality against it. Once a config works, it keeps working.

The loop is IaC-shaped:

```
declare (opsec.yaml)  →  verify (drift check)  →  apply (converge)  →  lock
```

## Install

```bash
cd faceless-engine
pip install -e .
```

If `fle` isn't on your PATH after install, use `python -m fle`.

## Quickstart

```bash
fle init            # write opsec.yaml (guided)
fle verify          # check your posture right now
fle apply           # fix what can be fixed (safe/reversible)
fle lock            # pin known-good state
fle hook install    # re-check on every command
```

## How it works

- `opsec.yaml` declares your desired posture: an identity (the persona plus the
  real identity to guard against) and a list of controls.
- Each control has a stable catalog ID (`OPSEC-<DOMAIN>-<NNN>`) and is backed by a
  provider that observes actual system state.
- `fle verify` runs the providers and emits a posture report. Each control comes
  back as `ok`, `drift`, `violation`, `not_applicable`, `error`, or `not_enforced`.
- The posture is conformant when no control of severity `high` or above is failing
  (`drift`, `violation`, or `error`). A non-conformant `verify` exits `10`.
- The shell hook runs a fast `fle status` at every prompt, so drift shows up the
  moment it happens instead of waiting for you to remember to check.

## Example `opsec.yaml`

```yaml
opsec_version: 1
name: ghostwriter
identity:
  persona:
    git_name: ghostwriter
    git_email: ghost@pseudonymous.example
  real:                       # must never appear in persona-scoped state
    names:  ["Jane Q. Doe"]
    emails: ["jane@personal.example"]
posture:
  - control: OPSEC-IDENTITY-101                     # git identity == persona
  - control: OPSEC-SECRET-050                        # no secrets in the environment
  - control: OPSEC-SECRET-060
    params: { forbidden_paths: ["~/.aws/credentials", "~/.netrc"] }
  - control: OPSEC-EGRESS-001
    params: { interface: wg0 }                       # VPN interface present
  - control: OPSEC-DISK-001                          # volume encryption on
enforcement:
  on_command: warn            # block | warn | off  (per-command hook behavior)
  auto_remediate: safe        # off | safe | full
```

## Controls (v1 catalog)

| ID | Checks | Remediable |
|----|--------|-----------|
| `OPSEC-IDENTITY-101` | git identity equals the persona and never the real identity | yes |
| `OPSEC-SECRET-050` | no secret-like values in the environment | detect-only |
| `OPSEC-SECRET-060` | declared plaintext secret files are absent | detect-only |
| `OPSEC-EGRESS-001` | declared VPN interface is present (tunnel up) | detect-only |
| `OPSEC-DISK-001` | system volume encryption is enabled | detect-only |

See [`SPEC.md`](SPEC.md) for the full standard: schema, catalog, conformance, and
report format. The JSON Schemas live in [`schema/`](schema/).

## Commands

| Command | Purpose |
|---|---|
| `fle init` | write `opsec.yaml` (guided) |
| `fle verify` / `plan` | evaluate posture; `--fast` `--json` `--sarif` `--quiet` `--no-lock` |
| `fle apply` | converge failing, remediable controls (`--full` for destructive) |
| `fle lock` | pin the current known-good posture to `opsec.lock.yaml` |
| `fle status` | one-line summary for the shell prompt |
| `fle hook install\|uninstall` | wire/unwire the per-command hook |

For machine output, `--json` is the canonical report and `--sarif` exports SARIF
2.1.0 for CI or code-scanning tools.

## Extending

Add a control by writing a provider: subclass `fle.providers.base.Provider`,
implement `observe()` (and `enforce()` if remediable), register it, and add a
catalog entry in `fle/catalog.py`. That is the only extension point.

## Tests

```bash
pip install -e ".[dev]"
pytest
```
