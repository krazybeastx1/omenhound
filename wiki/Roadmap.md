# Roadmap

OmenHound is built in **honest increments**: every capability ships with a test, and
every gap is reported rather than faked. This page is the current boundary.

## Shipped

- **Collector** — LDAP simple bind over **LDAPS**; users, groups, computers, domains and
  group membership; SRV-based DC discovery; BloodHound.py-compatible flags.
- **ACL collection** (`-c acl`) — reads each object's `nTSecurityDescriptor` (owner +
  DACL) and emits the same edges BloodHound.py would: `Owns`, `GenericAll`,
  `GenericWrite`, `WriteDacl`, `WriteOwner`, `AddMember`, `AddSelf`,
  `AllExtendedRights`, `GetChanges`, `GetChangesAll`, `GetChangesInFilteredSet`,
  `ForceChangePassword`, `ReadLAPSPassword`, `WriteSPN`, `AddKeyCredentialLink`,
  `WriteAccountRestrictions`, `AddAllowedToAct`, `WriteGPLink`. The pass is
  self-sufficient: it also creates the `OU`/`GPO`/`Container` nodes and any missing
  ACE-principal nodes. *Status:* the descriptor parser and ACE→edge mapping are
  unit-tested against **impacket**-generated descriptors; the live LDAP path is
  **code-only** (no AD lab available).
- **Container collection** (`-c container`) — GPOs, OUs and containers keyed by
  `objectGUID`; `Contains` edges for each container's direct children and
  `GPO -GPLink-> container` edges with `enforced` recorded. Disabled links are omitted
  as BloodHound.py omits them, and a link whose GPO was not enumerated keeps its edge by
  taking the GUID from the link DN. *Status:* the parsing/mapping helpers are
  unit-tested; the live LDAP path is **code-only** (no AD lab available).
- **Trust collection** (`-c trusts`) — `trustedDomain` objects become `TrustedBy` edges
  between `Domain` nodes in BloodHound's direction, with trust type, transitivity and
  SID-filtering carried on the edge. `-c dc` / `-c dconly` now expands to fully
  implemented methods. *Status:* parsing/mapping unit-tested; live path **code-only**.
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
| **Sessions & local-admin** | SMB/NetSession enumeration and `AdminTo`/`CanRDP`/`CanPSRemote` results. |
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
