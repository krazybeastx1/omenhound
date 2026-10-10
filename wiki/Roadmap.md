# Roadmap

OmenHound is built in **honest increments**: every capability ships with a test, and
every gap is reported rather than faked. This page is the current boundary.

## Shipped

- **Collector** — LDAP simple bind over **LDAPS**; users, groups, computers, domains and
  group membership; SRV-based DC discovery; BloodHound.py-compatible flags.
- **BloodHound CE interop** — import CE v5 JSON / BloodHound.py `--zip` (with ACE,
  session, local-admin, delegation, trust and GPO-link mapping), and export a native CE
  v5 archive via `--zip`.
- **Neo4j backend** — CE labels/relationships, SID identity, uniqueness constraints,
  batched `UNWIND` writes; in-memory store for demos/tests.
- **Abuse engine** — a rendering template for **every** supported edge, interpolating
  real node properties, with alternates, OPSEC, event IDs and explicit warnings.
- **Web UI** — dependency-free canvas force graph, node inspector, per-edge abuse panel,
  search, and the token-gated write API.
- **Hardening** — plaintext-LDAP refusal, memory-only TTL credentials with zeroing, TLS
  1.2+ for AD writes, bearer-token auth (constant-time), per-action approval on password
  changes, security headers, rate limiting, pagination, strict ingest, and a redacting
  audit log.

## In progress / next

| Item | Notes |
|---|---|
| **Native CLI parity** | Broaden direct collection so fewer gaps need an import bridge. |
| **ACL / SDDL collection** | Enumerate `nTSecurityDescriptor` and emit the ACL-derived edges natively. |
| **Sessions & local-admin** | SMB/NetSession enumeration and `AdminTo`/`CanRDP`/`CanPSRemote` results. |
| **GPO / OU / trust collection** | Complete `GPLink`, `Contains` and `TrustedBy` collection natively. |
| **Incremental merge** | SID-keyed incremental re-collection with **stale-edge expiry** (edges carry `first_seen`/`last_seen`). |
| **NTLM / Kerberos / pass-the-hash** | First-class `--hashes`, `-k/--kerberos`, `--auth-method`; fail loudly today. |

## Exploratory

- **Customised BloodHound CE frontend** options, with **stock-CE fallback** when the
  custom assets are absent.
- Additional import dialects (SharpHound legacy, other exporters).
- Query packs / canned attack-path reports surfaced in the UI.

## Non-goals

- Being a drop-in, byte-for-byte clone of BloodHound CE.
- Any auto-execution of abuse commands. OmenHound **renders** commands; a human runs
  them, deliberately.
- Silent partial results. If data isn't collected, it's reported.

## Compatibility promise

Until the roadmap items land, **`omenhound import` is the stable interface** for anything
OmenHound can't collect itself. Existing BloodHound CE / BloodHound.py output continues
to load into the CE-schema graph, and unsupported auth or methods fail loudly rather than
degrading silently.
