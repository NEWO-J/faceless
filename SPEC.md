# OpSec-as-Code: Specification v1

Status: draft. This document defines the OpSec-as-Code standard: the declarative
config format, the control catalog and its ID scheme, the provider contract, and
the conformance report format. `fle` is the reference implementation; any tool
that reads a conformant `opsec.yaml`, evaluates its controls, and emits a
conformant report is a conformant implementation.

## 1. Model

Operational security is expressed as **desired state**. A config declares a set
of **controls**; an implementation **observes** actual system state per control
and reports a **state**. The gap between desired and observed is **drift**.

```
declare (opsec.yaml)  →  verify (observe → report)  →  apply (converge)  →  lock (pin)
```

## 2. Config format (`opsec.yaml`)

Root is a mapping. JSON Schema: [`schema/opsec.schema.json`](schema/opsec.schema.json).

| Key | Required | Meaning |
|-----|----------|---------|
| `opsec_version` | yes | Must be `1`. |
| `name` | no | Human label for the posture. |
| `identity.persona` | no | String map of the operating identity (e.g. `git_name`, `git_email`). |
| `identity.real` | no | Identifiers that must never leak into persona-scoped state. |
| `posture` | yes | Non-empty list of control selections. |
| `posture[].control` | yes | A catalog control ID. |
| `posture[].severity` | no | Overrides the catalog default severity. |
| `posture[].params` | no | Control-specific parameters. |
| `enforcement.on_command` | no | `block` \| `warn` \| `off` (hook behavior). Default `warn`. |
| `enforcement.auto_remediate` | no | `off` \| `safe` \| `full`. Default `safe`. |

## 3. Control catalog

Controls have **stable IDs** in the scheme `OPSEC-<DOMAIN>-<NNN>`. IDs are
permanent: once assigned, an ID's meaning does not change; deprecated controls
are retired, not repurposed. Each control declares a domain, a default severity,
whether it is remediable, and whether it is *expensive* (too slow for the
per-command fast path, therefore cached).

Severity ordering: `low < medium < high < critical`.

v1 controls: see [`fle/catalog.py`](fle/catalog.py). Domains in use: `identity`,
`secret`, `egress`, `net`, `disk`, `privesc`.

A **bundle** is a named list of control IDs (for example `linux-net`,
`linux-privesc`). A `posture` entry of `{bundle: <name>}` expands to those
controls with their default severity. Bundles are ergonomic sugar over
selecting controls individually; they do not change the model.

## 4. Provider contract

Each control is backed by exactly one provider that:

- `observe(context) → CheckResult`: returns the current state. It must not mutate
  system state, and must not raise for expected conditions (return `error` instead).
- `enforce(context) → CheckResult` (optional): only for remediable controls. It
  converges actual state toward desired and may mutate system state.

An implementation MUST treat an unhandled provider exception as state `error`,
never as a crash of the whole evaluation.

## 5. States

| State | Meaning | Counts against conformance |
|-------|---------|----------------------------|
| `ok` | actual matches desired | no |
| `drift` | was/should be enforced, but changed | yes (if severity ≥ high) |
| `violation` | a prohibited condition is present | yes (if severity ≥ high) |
| `error` | could not be evaluated | yes (if severity ≥ high) |
| `not_applicable` | control does not apply (missing params/persona) | no |
| `not_enforced` | skipped (fast path, no provider) | no |

### Drift vs. lock

`fle lock` snapshots the `observed` values of every `ok` control to
`opsec.lock.yaml`. During later evaluation, an `ok` control whose observed values
differ from the lock MUST be reported as `drift`. This is what makes "once it
works, it always works" precise: known-good is pinned, and any deviation is drift.

## 6. Conformance

> A posture is **conformant** iff no control of severity ≥ `high` is in state
> `drift`, `violation`, or `error`.

A conformant `verify` exits `0`; a non-conformant one exits `10`. This single
rule is the interoperability contract: two implementations evaluating the same
config against the same system MUST agree on conformance.

## 7. Report format

The canonical report is JSON: [`schema/report.schema.json`](schema/report.schema.json).
It carries `opsec_version`, `conformant`, a `summary` (counts by state), and a
`results` array of per-control `{control, state, severity, summary, detail,
remediable, observed}`. A SARIF 2.1.0 export is provided for tool interop and is
derived from the canonical report (`violation`/`error` → `error`, `drift` →
`warning`).

## 8. Enforcement & the per-command hook

The standard defines *what* must hold, not *how* to trigger checks. The reference
implementation wires a shell hook that runs a fast `status` at every prompt and,
under `on_command: block`, best-effort refuses to submit a command while
non-conformant. On the fast path only the `safe` (reversible) remediation subset
may run automatically; `full` remediation is confined to an explicit `apply`.

## 9. Versioning

`opsec_version` gates breaking changes to the config/report shapes. New controls
and new domains are additive and do not bump the version. Removing or
re-meaning a control ID, or changing the conformance rule, requires a version
bump.
