# OmenHound Threat Model

| Field | Value |
|---|---|
| Document | `docs/THREAT-MODEL.md` |
| Component | OmenHound (`github.com/krazybeastx1/omenhound`) |
| Version | `dev` (link-time `internal/version.Version`) |
| Status | Living document — review on every change to `internal/creds`, `internal/api`, `internal/ingest` |
| Scope | Collector, ingestion API, Neo4j graph backend, web UI, credentials module, audit module, live credential-change feature |
| Method | Asset-centric, trust-boundary + STRIDE, dual-use (misuse) analysis |

OmenHound is not a passive observer. It authenticates to Active Directory with a
**live service account**, reads directory and host state, and — through the live
credential-change feature — **writes to AD by changing account passwords**. That
single capability moves the tool from "read-only scanner" to "authenticated AD
actor" and makes the tool itself part of the target's attack surface. This
document models both directions: what an adversary can do *to* OmenHound, and
what an adversary (or a compromised operator) can do *with* OmenHound.

The graph model (`pkg/model`) intentionally mirrors BloodHound CE so existing
Cypher queries and attack-path logic keep working. That compatibility goal is
itself a threat input: arbitrary operator-supplied queries are a first-class
attack vector against the backend.

---

## 1. System Overview

OmenHound is composed of the following packages and runtime units.

| Unit | Package / path | Role |
|---|---|---|
| Collector | `internal/collector` | Enumerates AD over LDAP/LDAPS, SMB, WinRM, RPC; emits `model.Graph` JSON |
| Ingestion API | `internal/ingest` | Receives collector `Graph` JSON, validates, writes to Neo4j |
| Graph backend | `internal/graph` | Cypher generation + Neo4j driver; stores nodes/edges |
| HTTP API | `internal/api` | Serves REST API and the web UI, auth (JWT), orchestrates collection |
| Web UI | `web/src` → `web/dist` | Operator console: view paths, run queries, trigger actions |
| Credentials module | `internal/creds` | Holds live AD creds in memory; binds secrets; performs credential changes |
| Credential-change | `internal/creds` (write path) | LDAPS `unicodePwd`, RPC `SamrChangePasswordUser` |
| Audit module | `internal/audit` | Append-only actor audit log, separate from Windows event logs |
| Abuse renderer | `internal/abuse` | Renders abuse commands from edge kinds (e.g. `ForceChangePassword`) |
| CLI | `cmd/omenhound` | `serve`, `collect`, `export` entrypoints |

### 1.1 Deployment reality

Typical deployment: a collector runs on a Windows or Linux host with line of
sight to domain controllers; the ingestion API and Neo4j run on an operator
host; the web UI is reached from an operator workstation. In lab/demo mode the
collector is bundled (`--collector sample`) and the API binds `127.0.0.1:8080`.
Production credentials must never be used in sample mode.

---

## 2. Assets

Assets are ranked by the impact of compromise. "Crown jewel" assets are the ones
that make OmenHound a high-value target.

| ID | Asset | Location | Why it matters |
|---|---|---|---|
| A1 | **Live AD service-account credentials** (password, NT hash, or certificate) | `internal/creds` memory; env / config / secret store | Direct, reusable domain access. Theft = full compromise of the collection identity. |
| A2 | **Changed-account credentials** — the new password written by the credential-change feature | `internal/creds` transient `[]byte` | If captured, gives the adversary the exact secret OmenHound just set. |
| A3 | **Collected graph data** (users, groups, computers, ACL edges, sessions, LAPS/GMSA reads) | Neo4j + `*.bh.json` exports | A complete AD attack map. Equivalent to months of manual recon. |
| A4 | **Audit logs** (actor audit JSONL) | `internal/audit`, `audit-*.jsonl` | Integrity of the who-did-what record; also a map of operator behavior. |
| A5 | **Operator session tokens / JWT signing key** | `internal/api` | Impersonation of an authorized operator; gateway to the write feature. |
| A6 | **The tool's own service account** (OS account running API/collector) | Host identity | May hold filesystem, secret-store, and network access; pivot point. |
| A7 | **Credential-change capability itself** | `internal/creds` write path | The ability to reset arbitrary AD passwords is the highest-blast-radius asset. |
| A8 | **Cypher query surface** | `internal/graph` | Injection point toward the graph store and, transitively, the backend host. |
| A9 | **Approval/MFA state** | API + UI | If bypassed, the write gate collapses. |

---

## 3. Trust Boundaries and Data Flow

### 3.1 Boundaries

| ID | Boundary | Crossing | Control expectation |
|---|---|---|---|
| TB1 | Browser ⇄ Web UI/API | HTTPS (TLS 1.2+) | TLS, JWT auth, CSRF protection, CSP |
| TB2 | API ⇄ Credentials module | In-process calls | Session-scoped memory-only secrets, never persisted |
| TB3 | Credentials module ⇄ AD (LDAPS/RPC) | LDAPS 636 + RPC | TLS to DC, no plaintext LDAP fallback |
| TB4 | Collector ⇄ Ingestion API | HTTPS (mTLS preferred) | TLS, auth, schema validation |
| TB5 | Ingestion API ⇄ Neo4j | Bolt/TLS | TLS, least-privilege DB user, parameterized Cypher |
| TB6 | API/Collector ⇄ Audit sink | Local append / remote syslog | Append-only, off-host copy, tamper evidence |
| TB7 | Build/release ⇄ Operator host | Artifacts, deps | Supply-chain integrity, module checksums |

### 3.2 Data-flow diagram

```
                         +-------------------------------------------+
                         |        Operator Workstation               |
                         |   browser: http(s)://<api>/  (TB1)        |
                         +------------------+------------------------+
                                            | TLS + JWT + CSRF
                                            v
   +---------------------+        +---------+----------------------------+
   |  Windows / Linux    |        |        OmenHound API service         |
   |  Collector host     |        |  internal/api    (HTTP router, JWT)  |
   | internal/collector  |        |  internal/ingest (Graph JSON intake) |
   |  LDAP SMB WinRM RPC |        |                                      |
   +----------+----------+        |  +----------------+  +-------------+ |
              |                   |  | session creds  |  |  audit      | |
   (TB3) LDAPS|636 / RPC          |  | internal/creds |  | internal/   | |
              v                   |  | memory-only    |  | audit (TB6) | |
   +----------+----------+        |  +-------+--------+  +------+------+ |
   |  Active Directory   |<-------+----------+------------------+        |
   |  Domain Controllers |  write |          |                           |
   |  (crown jewel A1/A7)|  path  |          |                           |
   +---------------------+  (TB3) |          v                           |
                                  |  +------+-----------------------+   |
                                  |  | internal/graph  (Cypher)     |   |
                                  |  +--------------+---------------+   |
                                  +-----------------|-------------------+
                                                    | Bolt/TLS (TB5)
                                                    v
                                            +-------+--------+
                                            |   Neo4j        |
                                            | nodes + edges  |
                                            | (A3)           |
                                            +----------------+

   Collector --Graph JSON / HTTPS (TB4)--> internal/ingest --> internal/graph --> Neo4j
```

**Highest-risk edges:** the write path across TB3 (`internal/creds` → DC), the
secret handoff across TB2, and the operator-controlled Cypher across TB5.

---

## 4. Adversary Profiles

| ID | Adversary | Goal | Position | Notes |
|---|---|---|---|---|
| ADV-1 | **External attacker** | Reach the API/UI or ingestion endpoint over the network | Internet or adjacent network | Attacks unauthenticated endpoints, weak JWT, TLS gaps, exposed Bolt. |
| ADV-2 | **Malicious insider** | Exfiltrate the AD map or escalate via the write feature | Valid operator or admin account | Has legitimate tokens; abuse looks like normal use unless audited. |
| ADV-3 | **Compromised operator** | Same as ADV-2 but via stolen session/malware on workstation | Browser session, workstation host | Token theft via XSS, infostealer, or shared machine. |
| ADV-4 | **Supply chain** | Implant into dependencies, build, or UI bundle | Upstream modules, `web/dist`, release pipeline | Go module substitution, tampered artifact, malicious npm dep. |
| ADV-5 | **Co-tenant / lab neighbor** | Steal creds left in a shared lab | Shared host, sample config | Demo/sample mode with real creds is the classic failure. |
| ADV-6 | **AD-native attacker** | Use the tool as a discovery/lateral-movement aid after initial foothold | Elevated domain user | Targets the tool's service account and Neo4j data (A6, A3). |

ADV-2/ADV-3 are the most dangerous because OmenHound hands a *legitimate* user a
domain-write capability. The tool's own controls, not AD permissions alone, are
what bound the blast radius.

---

## 5. STRIDE Analysis per Component

### 5.1 Collector (`internal/collector`)

| STRIDE | Threat | Impact |
|---|---|---|
| Spoofing | Rogue LDAP/DC response or MITM injects false topology | Poisoned attack paths, misdirected remediation |
| Tampering | Collected `Graph` JSON altered in transit (TB4) | Fabricated/noised graph |
| Repudiation | Collection performed without a durable record of the account used | Unattributable recon |
| Info. disclosure | Credentials or session data leak into collector logs/debug | Credential exposure |
| DoS | Collector floods a DC; is itself hung by a slow LDAP query | DC impact, denied collection |
| Elev. of privilege | Collector runs with excess host/dir rights | Pivot to A6 |

### 5.2 Ingestion API (`internal/ingest`)

| STRIDE | Threat | Impact |
|---|---|---|
| Spoofing | Unauthenticated/mTLS-missing collector pushes a forged graph | Data integrity loss |
| Tampering | Oversized or malformed JSON changes DB state | Corruption / DoS |
| Repudiation | Ingest accepted with no actor/collector provenance | Audited-clean-write problem |
| Info. disclosure | Verbose decode errors echo payload contents | Leakage of graph/creds in logs |
| DoS | Unbounded JSON body → memory exhaustion | Service outage |
| Elev. of privilege | **Deserialization of collected JSON** into richer types; parser trust | Arbitrary object/DoS (see RISK-08) |

### 5.3 Neo4j graph backend (`internal/graph`)

| STRIDE | Threat | Impact |
|---|---|---|
| Spoofing | Fake Bolt endpoint / missing TLS | Credential + data interception |
| Tampering | Cypher injection via UI query or node props | DB/host compromise |
| Repudiation | Cypher executed under shared DB user | No per-operator attribution |
| Info. disclosure | DB reachable without auth; bulk export of A3 | Full AD map exfiltration |
| DoS | Unbounded query (`MATCH (n) ... `, cartesian) | Backend hang |
| Elev. of privilege | Cypher escalated to filesystem/editor (`LOAD CSV`, APOC) | Backend RCE |

### 5.4 Web UI / HTTP API (`internal/api`, `web/`)

| STRIDE | Threat | Impact |
|---|---|---|
| Spoofing | Weak/forged JWT; alg confusion; no audience/issuer check | Operator impersonation |
| Tampering | CSRF on state-changing endpoints | Unauthorized write actions |
| Repudiation | No UI-action audit trail | Denied actions |
| Info. disclosure | XSS steals token; verbose errors; **password fields in DOM/logs** | A2/A5 leakage |
| DoS | Expensive graph queries triggered from UI | Outage |
| Elev. of privilege | **SSRF** via collector/import URLs; **path traversal** in export/static file serving | Internal access, file read (RISK-06/07) |

### 5.5 Credentials module (`internal/creds`)

| STRIDE | Threat | Impact |
|---|---|---|
| Spoofing | Impostor API call invokes the secret-handling path | Unauthorized secret use |
| Tampering | In-memory creds overwritten by a co-resident bug | Auth failures / silent misuse |
| Repudiation | Secret use not logged | Unattributable credential use |
| Info. disclosure | **Credential theft from the tool**: core dump, swap, `[]byte` not zeroed, debug dump | Full domain compromise (A1/A2) |
| DoS | Secret store unavailable → collection/write fails | Operational impact |
| Elev. of privilege | Over-broad service-account rights mean any read of the secret is maximum impact | Blast radius = domain |

### 5.6 Audit module (`internal/audit`)

| STRIDE | Threat | Impact |
|---|---|---|
| Spoofing | Forged audit entries attributed to another actor | Framing / cover |
| Tampering | Log file edited/truncated by local attacker | Evidence loss |
| Repudiation | **Log leakage of passwords** blurs but also poisons the record | Secret exposure (A2) |
| Info. disclosure | Audit readable by low-priv host users | Recon of operator behavior |
| DoS | Log volume fills disk | Outage / log loss |
| Elev. of privilege | Audit contents used as a credential source | Escalation |

### 5.7 Credential-change feature (write path)

| STRIDE | Threat | Impact |
|---|---|---|
| Spoofing | Caller claims an approved change it did not get | Unauthorized password reset |
| Tampering | Target DN/SAM altered between approval and execution (TOCTOU) | Wrong account changed |
| Repudiation | Change not bound to an immutable actor + approval record | Deniable domain writes |
| Info. disclosure | New password logged/echoed/returned in API response | A2 exposure |
| DoS | Mass resets lock out the environment | Organizational outage |
| Elev. of privilege | **Abuse of the write feature** to take over privileged accounts | Full domain takeover (RISK-09) |

---

## 6. Specific Risks

Each risk has an ID, the STRIDE class, and a severity
(Critical / High / Medium / Low).

### RISK-01 — Credential theft from the tool (Info. disclosure — Critical)
The service account secret or the just-set password is resident in the API/collector
process. Vectors: core dumps, swap/pagefile, `ptrace`/process memory read on a
shared host, crash reporters, the Go race/debugger, and any place a `string`
copy of the secret survives GC. Go strings are immutable and cannot be reliably
zeroed; only `[]byte` buffers can be overwritten. Mitigation below addresses
`[]byte` + explicit zeroing, but *copy-on-read* hazards (fmt, `%s`, JSON
marshalling, logging) can silently create non-zeroable copies.

### RISK-02 — Plaintext LDAP / downgrade (Spoofing, Info. disclosure — High)
A collector configured with `ldap://` (389) or falling back from LDAPS on
failure exposes the service-account bind and all directory reads to MITM. A
plaintext bind also permits **credential replay** if the password crosses the
wire. Requires enforced LDAPS with no fallback.

### RISK-03 — Over-broad service-account rights (Elev. of privilege — Critical)
BloodHound-style collection needs broad read (Replicating Directory Changes,
membership, ACLs). If the configured account is Domain Admin or holds write
rights used only for the credential feature, then compromise of A1 is
equivalent to domain compromise. Collection read and write should use separate
identities, neither Domain Admin.

### RISK-04 — SSRF via UI/import (Elev. of privilege — High)
An operator-supplied "import from URL", "collector target", or "test
connection" parameter can be pointed at `http://169.254.169.254/` (cloud
metadata), `http://localhost:<neo4j>/`, or internal admin endpoints. The API
becomes a proxy into the internal network. Requires scheme/host allow-lists and
egress policy, not just input validation.

### RISK-05 — Injection via the UI (Elev. of privilege — High)
Unvalidated node props, search terms, or rendered abuse commands can flow into
Cypher, shell (abuse-command rendering), or the DOM. The abuse renderer is
especially exposed: it turns edge kinds like `ForceChangePassword` into
executable command text. Untrusted props interpolated into that text are a
command-injection vector for a copy-paste operator.

### RISK-06 — Path traversal (Info. disclosure — Medium/High)
Export/import and static-file serving (`web/dist`) must not accept `../`.
Traversal reaches config, `.env`, `audit-*.jsonl`, or a stored `*.bh.json`
graph. See `.gitignore` intent: "never commit locks, dumps, creds, or audit
logs" — the same files are the traversal targets that matter.

### RISK-07 — Deserialization of collected JSON (Elev. of privilege — High)
`internal/ingest` decodes attacker-influenceable `model.Graph`. Today the types
are flat (`[]Node`, `[]Edge` with `map[string]string` props), which limits
`interface{}` gadget risk — but any future generic decode, plugin, or
`map[string]any` expansion reintroduces classic unsafe-deserialization impact.
Body size, depth, and node counts must be bounded.

### RISK-08 — Graph query injection / unsafe Cypher (Elev. of privilege — Critical)
The BloodHound-compatibility goal encourages arbitrary operator Cypher. If
query text or identifiers are string-concatenated, an operator (or XSS-driven
request) can run writes (`SET`, `DELETE`), exfiltrate (`LOAD CSV`), or reach
APOC procedures for **code execution** on the Neo4j host. All Cypher must be
parameterized; the query console must be read-only and sandboxed.

### RISK-09 — Abuse of the credential-change feature (Elev. of privilege — Critical)
The write feature is a targeted AD takeover primitive. A malicious insider or a
stolen operator session can reset a privileged account, then authenticate as it.
This is the single most consequential misuse path and must be gated by MFA +
approval + lab/opt-in, with rate and scope limits.

### RISK-10 — Log leakage of passwords (Info. disclosure — High)
Passwords appearing in audit entries, HTTP access logs, error messages, panic
stack traces, or the *response body* of a change call. Even a "success" message
that echoes the new secret leaks A2. The audit record must reference the action
and target only, never the secret.

### RISK-11 — JWT / session issues (Spoofing — High)
`alg:none`/HMAC-confusion, missing signature verification, no `exp`/`aud`/`iss`
checks, tokens not invalidated on logout, secret-key reuse across environments,
or JWT in a URL. Combined with XSS, token theft yields operator impersonation
and access to the write gate.

### RISK-12 — Neo4j exposure & shared DB identity (Info. disclosure, Repudiation — High)
Neo4j reachable with default/weak auth, or all operators using one DB user,
removes both confidentiality and attribution. Bolt must be TLS-only and
least-privilege, one logical identity per deployment at minimum.

### RISK-13 — Audit log tamperability (Tampering, Repudiation — Medium)
A local append-only file can be edited by a host-level attacker. Without an
off-host copy or hash chaining, ADV-2/ADV-6 can erase their tracks.

### RISK-14 — Supply-chain / tampered artifact (Tampering — High)
Go module substitution, a malicious dependency, a tampered `web/dist` bundle, or
a release binary lacking provenance. A backdoor here inherits A1/A7 regardless
of the controls below.

### RISK-15 — Lab/demo mode confusion (Info. disclosure — Medium)
`run-sample` binds `127.0.0.1:8080` with a sample collector. If an operator
injects real credentials into sample mode, or exposes sample mode beyond
loopback, the bundled convenience becomes an exposure.

### RISK-16 — Data-at-rest exposure (Info. disclosure — Medium)
`*.bh.json` exports and Neo4j data files (A3) sit unencrypted on disk; backups
copy them elsewhere. At-rest encryption and retention limits are required.

---

## 7. Mitigations Already Chosen

These are design commitments, not aspirations. Deviations are security bugs.

| ID | Commitment | Counters |
|---|---|---|
| M1 | **Session-scoped, memory-only credentials stored as `[]byte` and explicitly zeroed after use.** Never written to disk, config, or the graph. | RISK-01, A1/A2 |
| M2 | **Never log the password field.** Structured logging redacts secret fields at the sink boundary; audit records store action + target, not secrets. | RISK-10, A4 |
| M3 | **TLS everywhere: browser → backend → LDAPS.** HTTPS for UI/API and ingestion; LDAPS 636 for directory; TLS for Bolt. | RISK-02, RISK-12 |
| M4 | **No plaintext LDAP.** `ldap://` is rejected; no LDAPS→LDAP downgrade fallback. | RISK-02 |
| M5 | **MFA/approval gating on write actions.** Credential changes require an explicit, independently approved request before execution. | RISK-09, A9 |
| M6 | **Full actor audit logging, separate from AD event logs.** Every read/write/collection/change is attributed to an operator identity in an append-only log the tool controls. | RISK-13, ADV-2/3 |
| M7 | **Opt-in / lab-gated credential-ops.** The write feature is off by default, enabled only in an explicit lab/authorized mode. | RISK-09, RISK-15 |
| M8 | **BloodHound-compatible schema with SID/objectGUID node IDs** (`pkg/model`) — stable identity aids integrity checks and idempotent ingest. | RISK-07, RISK-08 |

### 7.1 Mitigation implementation notes

- **M1 (zeroing):** zero via a helper that loops the `[]byte` and calls
  `runtime.KeepAlive` after zeroing so the compiler cannot elide it. Keep the
  number of secret copies at one. Avoid `fmt.Sprintf("%s", secret)`,
  `json.Marshal(secret)`, and `string(secret)` — each produces a non-zeroable
  copy. Reject secrets in `Props` (`map[string]string`) on ingest.
- **M2 (redaction):** prefer a typed `Secret` wrapper whose `String()`/`MarshalJSON()`
  emit `"[REDACTED]"`, so accidental logging fails safe.
- **M3/M4 (TLS):** pin/verify the DC certificate or trust the enterprise CA; do
  not disable verification "temporarily". Record the negotiated protocol in audit.
- **M5/M7 (write gate):** approval must be bound to `(actor, target, action,
  nonce)` and re-checked at execution time (close the TOCTOU in RISK-09).
- **M6 (audit):** hash-chain entries; ship a copy off-host over TLS; keep the
  write-path audit mandatory and non-skippable.

---

## 8. Residual Risks and Hardening Recommendations

Residual risk remains after the chosen mitigations. Ranked by urgency.

### 8.1 Residual risks

| ID | Residual risk | Why it persists |
|---|---|---|
| R-1 | In-memory secret exposure via core/swap/`ptrace` | Go offers no mlock guarantee; OS may swap the page. |
| R-2 | Accidental secret copies from formatting/serialization | Requires discipline + linters; not compiler-enforced. |
| R-3 | Write-feature abuse by a *fully authenticated, approved* insider | Approval is policy, not cryptographic, against a malicious approver. |
| R-4 | Operator-supplied Cypher compatibility surface | Inherent to BloodHound parity. |
| R-5 | Host-level audit tampering before off-host shipping | Small window between write and ship. |
| R-6 | Supply-chain compromise of a dependency or the UI bundle | Outside the code's direct control. |

### 8.2 Hardening recommendations

1. **Lock secret memory.** Where available use `mlock`/`LockOSThread` +
   platform memory locking for the secret buffer; disable core dumps
   (`RLIMIT_CORE=0`), and avoid secrets ever living in a `string`.
2. **Separate identities.** Distinct, least-privilege accounts for *read
   collection* vs *credential change*; neither is Domain Admin. Prefer
   authentication with short-lived certificates or gMSA over a static password.
3. **Enforce Cypher discipline.** Parameterized statements only; a read-only
   graph role; disable `LOAD CSV`, APOC, and `CREATE`/`SET`/`DELETE` in the
   console; cap result size and query timeout.
4. **SSRF hardening.** Scheme allow-list (`https`), DNS/IP deny-lists for
   link-local/metadata/loopback ranges, and an egress proxy. Validate after DNS
   resolution to defeat rebinding.
5. **Path and static-file safety.** Canonicalize and confine all paths; never
   serve `web/dist` with user-controlled segments; serve secrets/logs from no
   web route.
6. **Ingest hardening.** Cap body size, node/edge counts, and nesting depth;
   reject unknown fields; validate SID/objectGUID formats; authenticate
   collectors with mTLS.
7. **Token hardening.** Strong asymmetric or long random HMAC key per
   environment, `exp`/`nbf`/`aud`/`iss`/`jti`, short lifetimes, refresh-rotation,
   server-side revocation on logout, tokens only in `HttpOnly`/`Secure`/`SameSite`
   cookies, CSP + CSRF tokens for the UI.
8. **Audit integrity.** Hash-chain entries, monotonic sequence, ship over TLS
   immediately, alert on gaps. Treat audit write failure as a **hard failure**
   of the corresponding action.
9. **Write-feature safety rails.** Per-window rate limits, target allow-lists,
   a "dry-run/break-glass" mode, and a global kill switch. Two-person rule for
   privileged targets.
10. **Supply chain.** `go.sum` verification, vendoring or a checksum DB, SLSA-style
    provenance and signed releases, SBOM, dependency scanning, and a build that
    pins `web/dist` inputs.
11. **At-rest protection.** Encrypt Neo4j data and `*.bh.json` exports; enforce
    retention/deletion; never place A3 in a world-readable path.
12. **Runtime posture.** Run API/collector as a dedicated low-privilege OS user,
    read-only root filesystem, seccomp/no-new-privs, disabled core dumps, and
    network egress restricted to DCs and Neo4j.
13. **Testing.** Add abuse-case tests: JWT `alg:none`, traversal payloads, SSRF
    IPs, oversized JSON, Cypher injection strings, and secret-in-log assertions.
    Gate CI on `go vet` and a secret scanner.

### 8.3 STRIDE quick-reference

| Class | Primary OmenHound exposure |
|---|---|
| Spoofing | Forged JWT, rogue DC, forged collector |
| Tampering | Malicious ingest, log edits, tampered artifacts |
| Repudiation | Missing/weak actor audit on writes |
| Info. disclosure | A1/A2/A3 theft; log leakage of passwords |
| DoS | Graph queries, ingestion, mass credential resets |
| Elev. of privilege | SSRF, injection, Cypher, and the write feature |

---

## 9. Misuse / Authorization Notice (Dual-Use)

OmenHound is **dual-use security tooling**. It enumerates Active Directory and,
when explicitly enabled, changes AD account passwords. The same capability that
supports authorized red-team, purple-team, and defensive attack-path analysis
can be repurposed for unauthorized domain takeover.

Use of OmenHound is permitted **only** where all of the following hold:

1. You have **explicit, written authorization** from the owner of every domain,
   forest, host, and network the tool touches, and the authorization covers both
   read collection **and** credential modification.
2. Credential-ops remain **opt-in and confined to an authorized lab or
   engagement boundary** (per M7). The tool must never modify credentials in an
   environment you do not own or are not contracted to test.
3. You comply with all applicable laws, regulations, and the target's rules of
   engagement, including change windows and rate limits.

Operators are responsible for the consequences of every action the tool
performs under their session identity. The audit log (M6) exists precisely to
make that responsibility attributable. Do not disable it. Do not run
credential-ops outside an authorized scope. Do not use OmenHound to access
systems you do not own or lack permission to test.

This notice is not legal advice; obtain counsel for your jurisdiction.

---

*End of document. Review on any change to `internal/creds`, `internal/api`,
`internal/ingest`, or `internal/graph`.*
