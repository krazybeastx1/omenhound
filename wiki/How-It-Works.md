# How It Works

OmenHound is a small set of independent Go packages wired together by one binary.

```
                      Graph JSON
 collector ─────────────────────────▶ ingest ──▶ Store ──▶ Neo4j / memory
 (ldap · sample · BH import)            │
                                        ├──▶ API ──▶ Web UI (canvas graph)
                                        │        └─▶ abuse engine (edge → command + OPSEC)
                                        └──▶ audit (JSON-lines, redacted)
```

## Packages

| Package | Responsibility |
|---|---|
| `pkg/model` | Node/edge vocabulary, `Graph`, `Meta`, SID-keyed identity, O(1) dedup index. |
| `internal/collector` | `Collector` interface; `sample` and `ldap` collectors (LDAP + SMB/RPC passes); method planning; DC SRV discovery. |
| `internal/bloodhound` | BloodHound CE JSON/`--zip` **import** and **export**. |
| `internal/graph` | `Store` interface; `memory` (tests/demos) and `neo4j` (production) backends. |
| `internal/ingest` | Strict decode, validation (size, referential integrity, vocabulary), write. |
| `internal/api` | HTTP endpoints, bearer-token auth, security headers, rate limiting, embedded UI. |
| `internal/abuse` | Edge → dynamic command + alternates + OPSEC + event IDs + warnings. |
| `internal/creds` | Session-scoped, memory-only credential store with TTL and zeroing. |
| `internal/audit` | Redacting JSON-lines audit logger. |
| `internal/act` | The **only** package that writes to AD (`unicodePwd` over LDAPS). |
| `web` | Embedded static UI (`embed.FS`) — no build step, no CDN. |

## Data model

- **Node identity is the AD `objectSID`** (users, groups, computers, domains) or
  `objectGUID` (OUs, GPOs, containers) — stable and domain-unique. This is exactly what
  BloodHound CE uses, so imported objects and collected objects merge by SID.
- **Node kinds** mirror CE labels: `User`, `Group`, `Computer`, `Domain`, `OU`, `GPO`,
  `Container`, `Trust`, and `Base` (CE's placeholder label for a referenced-but-not-collected
  object).
- **Edge kinds** mirror CE relationship names (`GenericAll`, `WriteDacl`, `MemberOf`,
  `AdminTo`, `HasSession`, `GPLink`, `TrustedBy`, …) so existing BloodHound Cypher keeps
  working. See **[Neo4j Schema & Attack Paths](Neo4j-Schema-and-Attack-Paths)**.
- `Graph.Meta.Warnings` carries honest, non-fatal caveats (e.g. skipped collection
  methods) all the way through export and the API.

### Direction conventions (BloodHound CE compatible)

| Edge | Direction | Meaning |
|---|---|---|
| `MemberOf` | member → group | principal belongs to group |
| `GPLink` | GPO → container | GPO is linked at the OU/domain/site |
| `Contains` | container → child | structural containment |
| `TrustedBy` | trusted → trusting | source domain is trusted by target |
| `HasSession` | user → computer | user has a session on the host |
| `AdminTo` | principal → computer | principal is a local admin |
| `AllowedToDelegate` | computer → target | constrained delegation |
| `AllowedToAct` | principal → computer | RBCD (allowed to act on behalf) |

## The abuse engine

For a concrete edge `(src) —kind→ (tgt)`, `abuse.Render` interpolates **real node
properties** into an attack template:

- `{DOMAIN}`, `{DC}`, `{SOURCE_SAM}`, `{SOURCE_DN}`, `{SOURCE_SID}`, `{SOURCE_NAME}`
- `{TARGET_SAM}`, `{TARGET_DN}`, `{TARGET_SID}`, `{TARGET_NAME}`

Each template carries a summary, a primary command, alternates, an **OPSEC/detection**
note, Windows **event IDs**, and required preconditions. Any placeholder with no
backing data becomes an explicit `⚠ warning` rather than a silently broken command.

## Progressive hardening / performance

The current implementation is the result of a dedicated hardening + optimization pass:

- **Graph dedup** — `Graph` keeps O(1) node/edge indexes (`nodeIdx`/`edgeIdx`), so large
  collections don't degrade quadratically.
- **Store adjacency** — the memory store maintains `out`/`in` adjacency maps, making
  neighbor lookups O(degree) instead of O(E).
- **Batched Neo4j writes** — writes are grouped by label/relationship type and sent via
  `UNWIND` in batches (5000), cutting round-trips by orders of magnitude.
- **Strict ingest** — payloads are size-bounded (512 MiB), unknown JSON fields are
  rejected, and trailing JSON is refused.
- **API hardening** — `Content-Security-Policy`, `nosniff`, `HSTS` (on TLS), a per-IP
  token-bucket limiter plus a separate write-method limiter, pagination on list
  endpoints (default 1000, max 10000), and `clientIP` that deliberately ignores
  `X-Forwarded-For`.
- **Collector bounds** — dial timeouts (SMB gated by a TCP probe, 10 s dial / 30 s
  per-host RPC), paged LDAP searches (500/page, 500k entries cap, 60s server-side time
  limit), and a plaintext-LDAP refusal. The SMB pass runs computers sequentially (an
  OPSEC choice) under the run's `--timeout`.
- **Credential hygiene** — secrets are `[]byte`, length-capped, explicitly zeroed with
  `runtime.KeepAlive`, and swept by a background janitor; the audit logger redacts
  sensitive field names before writing.

## Single binary, no build step

`web/static` is embedded with `//go:embed`. The frontend is a vanilla-JS canvas force
graph — no npm, no bundler, no CDN — so `bin/omenhound` is fully self-contained and works
in an air-gapped environment.

Next: **[Web UI Guide](Web-UI-Guide)** →
