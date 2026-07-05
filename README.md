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
- Each control has a stable catalog ID (`FLE-<DOMAIN>-<NNN>`) and is backed by a
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
os:
  expect: whonix-workstation   # string or list; e.g. [tails, whonix-workstation]
identity:
  persona:
    git_name: ghostwriter
    git_email: ghost@pseudonymous.example
  real:                       # must never appear in persona-scoped state
    names:  ["Jane Q. Doe"]
    emails: ["jane@personal.example"]
posture:
  - control: FLE-IDENTITY-101                     # git identity == persona
  - control: FLE-SECRET-050                        # no secrets in the environment
  - control: FLE-SECRET-060
    params: { forbidden_paths: ["~/.aws/credentials", "~/.netrc"] }
  - control: FLE-EGRESS-001
    params: { interface: wg0 }                       # VPN interface present
  - control: FLE-DISK-001                          # volume encryption on
enforcement:
  on_command: warn            # block | warn | off  (per-command hook behavior)
  auto_remediate: safe        # off | safe | full
```

## Controls

The catalog groups controls by domain under the `FLE-<DOMAIN>-<NNN>` scheme.

**Cross-platform**

| ID | Checks | Remediable |
|----|--------|-----------|
| `FLE-IDENTITY-101` | git identity equals the persona and never the real identity | yes |
| `FLE-SECRET-050` | no secret-like values in the environment | detect-only |
| `FLE-SECRET-060` | declared plaintext secret files are absent | detect-only |
| `FLE-EGRESS-001` | declared VPN interface is present | detect-only |
| `FLE-DISK-001` | system volume encryption is enabled | detect-only |

**Network / egress leaks**

The network domain is the deepest, built around the leak vectors the privacy
community actually tests: DNS, IPv6, and WebRTC leaks, a real kill-switch, and
LAN-side broadcast hardening.

| ID | Checks |
|----|--------|
| `FLE-EGRESS-002` | default route rides the declared VPN interface |
| `FLE-NET-001` | DNS resolvers are all on the allowlist |
| `FLE-NET-002` | IPv6 is disabled or routed through the VPN |
| `FLE-NET-003` | firewall denies by default (kill-switch) |
| `FLE-NET-004` | no unexpected services listening on non-loopback |
| `FLE-NET-005` | DNS is encrypted (DNS-over-TLS) |
| `FLE-NET-006` | resolver is not the LAN gateway (ISP router) |
| `FLE-NET-007` | LLMNR is disabled (no hostname broadcast / hash capture) |
| `FLE-NET-008` | mDNS is not broadcasting the host |
| `FLE-NET-009` | IPv6 privacy extensions are enabled (RFC 8981) |
| `FLE-NET-010` | no MAC-derived (EUI-64) IPv6 address |
| `FLE-NET-011` | Wi-Fi MAC randomization is configured |
| `FLE-NET-012` | captive-portal connectivity check is disabled |
| `FLE-NET-013` | TCP timestamps disabled (no uptime fingerprint) |
| `FLE-NET-014` | public egress IP is not a forbidden (real) address |
| `FLE-NET-015` | requests egress through the Tor network |

`FLE-NET-014` is the definitive leak proof: it fetches your public IP and
fails if the outside world sees an address you flagged as real. It's opt-in
(declare `forbidden_ips`) and makes a network call, so it runs only when asked.
Everything else is passive and offline. Linux-specific controls report
`not_applicable` on other platforms, so one config runs cleanly everywhere.

**Operating-system target**

| ID | Checks |
|----|--------|
| `FLE-OS-001` | the running OS matches the `os.expect` you declared |

Declare a target OS and `FLE-OS-001` fails if you're not on it. It knows the
anonymity systems the community uses, so `expect: whonix-workstation` catches you
firing up sensitive work on the host or the Gateway by mistake. Detected values
include `tails`, `whonix-gateway`, `whonix-workstation`, `qubes`, ordinary distro
ids (`debian`, `ubuntu`, ...), `windows`, and `macos`. Umbrella terms work too:
`whonix` matches either Whonix VM, `anonymity` matches Tails/Whonix/Qubes, and
`linux` matches any distro.

**Browser fingerprinting resistance (Firefox / Tor Browser)**

The goal is uniformity, not uniqueness: a hardened browser makes you look like
everyone else in the Tor Browser crowd, which shrinks your fingerprint. These
controls verify that hardening is on. They read Firefox prefs and never spoof or
rotate anything.

| ID | Checks |
|----|--------|
| `FLE-BROWSER-001` | `privacy.resistFingerprinting` on (uniform UA, screen, timezone, canvas) |
| `FLE-BROWSER-002` | WebRTC disabled (no IP leak past the VPN) |
| `FLE-BROWSER-003` | canvas/WebGL fingerprinting mitigated |
| `FLE-BROWSER-004` | browser telemetry disabled |
| `FLE-BROWSER-005` | RFP letterboxing rounds the window size |

Pull them all in with `- bundle: browser-hardening`. Reports `not_applicable`
when no Firefox profile is found.

### Bundles

Pull a whole domain in with one line instead of listing each control:

```yaml
os:
  expect: whonix-workstation
posture:
  - bundle: whonix           # FLE-OS-001 + anonymity-OS leak checks
  - bundle: linux-net        # FLE-EGRESS-001/002 + FLE-NET-001..013
  - control: FLE-EGRESS-002 # also list a control to pass params
    params: { interface: wg0 }
```

Bundles `tails` and `whonix` verify the OS plus the leak checks that matter most
on an amnesic system (IPv6 off, no MAC-derived address, MAC randomization).

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
| `fle key` | show your attestation public key |
| `fle attest` | sign a posture attestation against a required baseline |
| `fle verify-attestation` | verify someone's attestation token |

For machine output, `--json` is the canonical report and `--sarif` exports SARIF
2.1.0 for CI or code-scanning tools.

## Group attestation

A room, team, or group can require members to prove they meet a shared posture
before they join. The room publishes a required `opsec.yaml`; a member proves
they satisfy it with a signed token that a gatekeeper (a chat bot or a person on
any platform) verifies.

```bash
# member: check against the room's baseline and sign a token
fle attest -c room-baseline.yaml --nonce "$CHALLENGE" --subject ghostwriter -o token.json

# gatekeeper: accept only if conformant, bound to this baseline, fresh, and unforged
fle verify-attestation token.json --baseline room-baseline.yaml --nonce "$CHALLENGE" \
    --max-age 600 --allow <member-pubkey>
```

The token is Ed25519-signed and bound to a hash of the exact baseline, so a
member cannot attest against a weaker config. It carries per-control pass/fail
but never the observed values, so you prove conformance without handing the room
your IPs, paths, or resolvers. The `--nonce` is a challenge from the gatekeeper
that stops replay of an old token.

**Trust model, stated plainly:** this is self-attested. A patched client can
forge a "conformant" report, so treat attestation as a *cooperative* control. It
makes everyone run the same check against the same baseline, catches honest drift
and misconfiguration, and proves freshness. It does not stop a determined liar.
Defeating that needs hardware attestation (TPM measured boot), which fle does not
attempt.

## Extending

Add a control by writing a provider: subclass `fle.providers.base.Provider`,
implement `observe()` (and `enforce()` if remediable), register it, and add a
catalog entry in `fle/catalog.py`. That is the only extension point.

## Tests

```bash
pip install -e ".[dev]"
pytest
```
