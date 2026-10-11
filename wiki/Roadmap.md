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
- **SMB/RPC collection** (`-c session,localadmin,rdp,dcom,psremote,loggedon`) — one
  authenticated SMB session per computer drives the same DCE/RPC calls BloodHound.py
  uses: srvsvc sessions and wkssvc logged-on users → `HasSession`; samr local aliases
  544/555/562/580 → `AdminTo`, `CanRDP`, `ExecuteDCOM`, `CanPSRemote`. BloodHound.py's
  filtering (self session, machine accounts, loopback, local SAM SIDs) and resolution
  (SAM-name index, reverse DNS, lsarpc `LsarLookupSids2` one SID per call) are
  reproduced. Computers are queried sequentially; `--hashes` works over SMB too.
  *Status:* filtering/resolution/wiring are unit-tested; the live SMB/RPC path is
  **code-only** (no SMB host available). *Divergences:* no port-139 fallback, no
  unauthenticated hostname lookup, `loggedon` is wkssvc-only — all reported as warnings.
- **Auth** — LDAP **simple bind** by default, **NTLM bind** (`--auth-method ntlm`) and
  **pass-the-hash** (`--hashes NT|LM:NT`) over LDAPS **and SMB**, using go-ldap's
  NTLMSSP bind for LDAP and the SMB library's NTLM initiator (raw NT hash) for SMB.
  `--hashes` implies NTLM; only the NT half is used. Cleartext NTLM is refused unless
  `--allow-plaintext-ldap`. **Kerberos** (`-k` / `--auth-method kerberos`) drives LDAP
  through a GSSAPI SASL bind and SMB through a cifs service ticket, from a password,
  NT hash (`--hashes`, overpass-the-hash), AES key (`--aes-key`) or an existing ccache
  (`--use-kcache`, `$KRB5CCNAME`). The SMB pass logs on **once** and reuses the TGT —
  one AS-REQ for the run, one TGS per host, like BloodHound.py. *Status:* hash/AES/key
  parsing, principal splitting, SPN construction, KDC selection, method resolution and
  every refusal are unit-tested; the NTLMSSP and Kerberos handshakes themselves are
  **code-only** (no AD lab available). Kerberos needs the DC **hostname**
  (`--server dc01.corp.local`), not an IP.
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
| **Incremental merge** | SID-keyed incremental re-collection with **stale-edge expiry** (edges carry `first_seen`/`last_seen`). |
| **Concurrent SMB** | The SMB pass is deliberately sequential (OPSEC); a bounded worker pool is the fast-mode follow-up. |
| **Delegation collection** | `AllowedToDelegate` / `AllowedToAct` are imported but not yet collected natively. |

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

OmenHound collects every BloodHound.py method natively, and **`omenhound import`** stays
the stable interface for anything else (existing CE data, delegation edges, other
exporters). BloodHound CE / BloodHound.py output continues to load into the CE-schema
graph, and an unknown auth method fails loudly rather than degrading silently.
