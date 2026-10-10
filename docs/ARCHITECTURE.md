# OmenHound — Architecture

> **Status:** Design baseline, grounded in the data model committed at
> `pkg/model/model.go`. **Module:** `github.com/krazybeastx1/omenhound` · **Go:** 1.26.
> OmenHound is an authorized-use tool; use it only with explicit written permission.

## 1. Overview, Goals, Non-Goals

OmenHound is a BloodHound-style Active Directory attack-path analysis tool
rewritten in Go. It collects AD relationships, stores them as a graph, and serves
a UI that lets an operator explore paths and render abuse commands for the AD
edges along those paths. Four first-class components:

1. **Collector** (`internal/collector`) — a static Go binary, the SharpHound
   equivalent. Speaks LDAP (`go-ldap`) and SMB (`go-smb2`); RPC/DCOM is planned.
   Emits a `model.Graph`. `methods.go` plans BloodHound.py-compatible collection
   methods (`-c …`) and performs DC SRV discovery; unimplemented methods are
   reported as explicit warnings and never silently dropped.
2. **BloodHound interop** (`internal/bloodhound`) — imports BloodHound CE v5 JSON
   and `bloodhound-ce-python --zip` archives into `model.Graph` (SIDs/GUIDs kept
   verbatim, CE edge directions, unmappable ACE rights counted), and exports an
   OmenHound graph as a native CE v5 archive (`--zip`). Import → export → import
   is lossless on the test fixture.
3. **Graph backend** (`internal/graph`) — a `Store` interface with in-memory
   (`memory.go`) and Neo4j (`neo4j.go`) implementations; the schema mirrors
   BloodHound CE so CE queries keep working.
4. **Ingestion/API service** (`internal/ingest`, `internal/api`) — accepts
   `model.Graph` payloads, persists them through the `Store`, answers graph
   queries, renders abuse commands, and serves the UI. Write endpoints (ingest,
   credentials, password change) require a bearer token; rate-limited, paginated.
5. **Web UI** (`web/static`) — a dependency-free vanilla-JS canvas force graph
   embedded in the binary, with a node inspector, per-edge abuse panel, search,
   and a token-gated write control. A customized BloodHound CE UI remains the
   planned alternative, with the stock CE UI as fallback.

### Goals

- **Single static binary** for collection and serving; no JVM/Python/Node.
- **BloodHound CE compatibility.** Same node labels, edge names, and `objectid`
  identity property, so CE Cypher queries and attack-path logic run unchanged.
- **Deterministic, diffable wire format.** One JSON graph document is the
  contract between every stage; any component is replaceable if it produces or
  consumes that document.
- **Safe, auditable defaults.** Abuse commands carry OPSEC annotations;
  credentials are memory-only; live credential-change is opt-in/gated/logged.
- **Testable without a domain.** A `sample` collector and memory `Store` run the
  whole pipeline via `make run-sample`.

### Non-Goals

- Not an identity-governance or SIEM product.
- Not a real-time event streamer (no Event Forwarding / ETW in v1).
- Not a remote-exploitation framework. OmenHound *renders* abuse commands and
  does not autonomously execute them; the one exception (live credential change)
  is gated in §6.6.
- Not Entra ID / Azure AD in v1 (planned, §9); no multi-tenant SaaS hosting.

## 2. Component Diagram

```text
                        operator host / lab
  ┌──────────────────────────────────────────────────────────────────┐
  │  omenhound collect                       omenhound serve          │
  │  ┌───────────────────────┐               ┌─────────────────────┐  │
  │  │ Collector interface   │               │ internal/api (HTTP) │  │
  │  │  ├─ ldap.go           │  model.Graph  │  /api/v1/ingest     │  │
  │  │  ├─ smb.go            ├──(JSON POST)─►│  /api/v1/paths      │  │
  │  │  ├─ sample.go         │  /api/v1/     │  /api/v1/abuse      │  │
  │  │  └─ (rpc/dcom)        │  ingest       │  /  (web UI)        │  │
  │  └───────────────────────┘               └──────────┬──────────┘  │
  │                                                     │             │
  │  ┌───────────────┐  ┌───────────────┐    ┌──────────▼──────────┐  │
  │  │ abuse (tmpl)  │  │ creds (mem)   │    │ internal/ingest     │  │
  │  ├───────────────┤  ├───────────────┤    │  validate + merge   │  │
  │  │ audit (JSONL) │  │               │    └──────────┬──────────┘  │
  │  └───────────────┘  └───────────────┘               │ Store iface │
  │                                          ┌──────────▼──────────┐  │
  │                                          │ internal/graph      │  │
  │                                          │  ├─ memory.go       │  │
  │                                          │  └─ neo4j.go ───────┼──┼─► Neo4j
  │                                          └─────────────────────┘  │
  └──────────────────────────────────────────────────────────────────┘
                      │
                      ▼
               AD domain (LDAP/SMB)
```

The collector **never talks to Neo4j directly**; its only output is a
`model.Graph` document. That keeps collection portable (air-gappable), keeps
persistence in one place, and lets the sample collector run with no network.

## 3. Data Model

Authoritative definitions live in `pkg/model/model.go`; below is that file plus
the conventions layered on top.

### 3.1 Node kinds

`model.Kind` is a string type whose values match BloodHound CE labels:

| `Kind`      | Meaning in AD                                   |
|-------------|-------------------------------------------------|
| `User`      | User account object                             |
| `Group`     | Security/distribution group                     |
| `Computer`  | Machine account object                          |
| `Domain`    | AD domain (forest/domain trust root)            |
| `OU`        | Organizational Unit                             |
| `GPO`       | Group Policy Object                             |
| `Container` | Generic container, including default containers |
| `Trust`     | A trust relationship modeled as a node          |

### 3.2 Node

```go
type Node struct {
    ID             string            `json:"id"`                       // SID (or objectGUID)
    Kind           Kind              `json:"kind"`                     // label
    Name           string            `json:"name"`
    Domain         string            `json:"domain,omitempty"`
    SAMAccountName string            `json:"sam_account_name,omitempty"`
    DN             string            `json:"distinguished_name,omitempty"`
    Props          map[string]string `json:"props,omitempty"`          // open attribute bag
}
```

`Props` is the escape hatch: attributes (`enabled`, `admincount`, `pwdlastset`,
`lastlogon`, `serviceprincipalnames`, …) travel without struct changes.
`Graph.AddNode` de-duplicates on `ID` and **replaces** on collision, so later
collection phases win (last-write-wins).

### 3.3 Edge kinds

`model.EdgeKind` values are relationship names and double as the abuse-renderer
keys. **ACL/rights:** `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`,
`ForceChangePassword`, `Owns`, `ReadLAPSPassword`, `ReadGMSAPassword`.
**Membership/control:** `AddMember`, `AddSelf`, `AllowedToDelegate`,
`AllowedToAct`. **Remote access:** `AdminTo`, `CanPSRemote`, `ExecuteDCOM`,
`HasSession`. **Directory relations:** `MemberOf`, `DCSync`, `GetChanges`,
`GetChangesAll`, `Contains`, `GPLink`. **Trusts:** `TrustedBy`.

### 3.4 Edge

```go
type Edge struct {
    Source string            `json:"source"`   // Node.ID
    Target string            `json:"target"`   // Node.ID
    Kind   EdgeKind          `json:"kind"`     // relationship type
    Props  map[string]string `json:"props,omitempty"`
}
```

Edges are **directed Source -> Target**. `Graph.AddEdge` de-duplicates on
`(Source, Target, Kind)`, making ingestion idempotent: replaying a graph is a
no-op. `Props` carries `inherited`, `isacl`, `lastseen`, and ACE
rights/inheritance details.

### 3.5 Graph, Meta, and the wire format

```go
type Meta struct {
    Collector  string    `json:"collector"`   // "ldap", "smb", "sample", "composite"
    Version    string    `json:"version"`     // binary version (internal/version)
    Domain     string    `json:"domain,omitempty"`
    StartedAt  time.Time `json:"started_at"`
    FinishedAt time.Time `json:"finished_at"`
}

type Graph struct {
    Nodes []Node `json:"nodes"`
    Edges []Edge `json:"edges"`
    Meta  Meta   `json:"meta"`
}
```

`model.Graph` **is** the wire format: the payload of `POST /api/v1/ingest`, the
output of `omenhound collect`, and the on-disk format of `omenhound export`. Its
guarantees:

- **Self-describing.** `Meta.Collector`/`Meta.Version` identify provenance so
  ingestion can branch on collection method.
- **Referentially closed.** Every `Edge.Source`/`Edge.Target` MUST resolve to a
  `Node.ID` in the same document (or already be present for an incremental
  push); dangling edges are rejected/quarantined.
- **Additive.** New kinds/fields are added, never repurposed; very large domains
  may emit the same shape as NDJSON (§9).

### 3.6 Why SIDs are the identity key

`Node.ID` is the AD SID (`objectSid`), falling back to `objectGUID` when no SID
exists. Reasons:

1. **Stability.** SIDs survive renames, OU moves, and DN changes, so a principal
   keeps one graph identity and saved queries stay valid.
2. **Forest uniqueness.** SIDs are unique per domain and globally unique across
   trusts once the domain SID prefix is included — key for cross-domain traversal.
3. **ACLs are SID-based.** Windows ACEs reference trustees by SID, so ACL
   collection is lossless only if SIDs are the join key.
4. **Collision resistance & parity.** SAM/display names collide (`Administrator`
   in every domain, duplicate `svc_*`) while SIDs do not, and BloodHound CE keys
   nodes on the SID in `objectid`.

`SAMAccountName`, `Name`, and `DN` are payload, not identity: indexed for search,
never used for joins.

## 4. Collector Design

### 4.1 The interfaces

Two small interfaces decouple collection from persistence.

```go
// internal/collector
type Collector interface {
    Name() string
    Collect(ctx context.Context, opts Options) (*model.Graph, error)
}
```

`Options` carries connection + scope: `Domain`, `DomainController`, `BaseDN`,
`Username`, `Password`/`Hash` (from `internal/creds`, never logged), `TLS`,
`Method` (LDAP/SMB/RPC/ALL), `Threads`, `Throttle`, `Full`, and category toggles
(`Sessions`, `ACLs`, `GPOs`, `Trusts`).

```go
// internal/graph
type Store interface {
    UpsertNodes(ctx context.Context, nodes []model.Node) error
    UpsertEdges(ctx context.Context, edges []model.Edge) error
    GetNode(ctx context.Context, id string) (model.Node, bool, error)
    Neighbors(ctx context.Context, id string, dir Direction, kinds ...model.EdgeKind) ([]model.Edge, error)
    ShortestPath(ctx context.Context, from, to string) ([]model.Edge, error)
    ExpireStaleEdges(ctx context.Context, olderThan time.Time) (int, error)
    Snapshot(ctx context.Context) (*model.Graph, error) // used by `export`
    Close() error
}
```

The `Collector` produces a `model.Graph`; the `Store` consumes one. The collector
is unaware of Neo4j, the store is unaware of LDAP, and both are trivially
fakeable in tests.

### 4.2 LDAP collection (`ldap.go`)

Primary collector, built on `go-ldap`:

1. **Bind.** Authenticate to the DC (simple bind, or NTLM/SASL where offered);
   credentials from `internal/creds` are zeroized after bind.
2. **RootDSE + naming contexts.** Discover `defaultNamingContext`,
   `configurationNamingContext`, `rootDomainNamingContext`, supported controls.
3. **Directory walk.** One paged search per category: **Users**
   `(&(objectCategory=person)(objectClass=user))` → `objectSid`, `sAMAccountName`,
   `distinguishedName`, `userAccountControl` (→ `enabled`, admin bits),
   `adminCount`, `pwdLastSet`, `lastLogon`, `servicePrincipalName`, `memberOf`,
   `primaryGroupID`; **Groups** `(objectCategory=group)` → `member`, `groupType`,
   well-known RIDs; **Computers** `(objectCategory=computer)` → `operatingSystem`,
   `operatingSystemVersion`, `lastLogon`, `dNSHostName`; **GPOs**
   (`groupPolicyContainer`) → `displayName`, `gPCFileSysPath`, `gPLink`,
   `gPOptions`; **OUs/Containers** for structure and GPO linkage; **Domains** →
   `trustDirection`, `trustPartner`, `trustType`, `trustAttributes`.
4. **ACL collection.** Read `nTSecurityDescriptor` (requesting the
   `LDAP_SERVER_SD_FLAGS_OID` control as needed), parse the DACL, and map each
   ACE's `AccessMask` + trustee SID + object-type GUID to an `EdgeKind`
   (`ADS_RIGHT_GENERIC_ALL` → `GenericAll`; `WD`/`WO`/`DC` bits →
   `WriteDacl`/`WriteOwner`; extended-right GUIDs → `DCSync`,
   `ForceChangePassword`, `AllowedToAct`, …). Inheritance flags land in
   `Edge.Props["inherited"]`.
5. **Membership edges.** `primaryGroupID` is not in `member`, so a `MemberOf`
   edge is synthesized from `primaryGroupID` + domain SID.
6. **Materialize** a `model.Graph` with `Meta.Collector = "ldap"`.

### 4.3 SMB collection (`smb.go`)

`go-smb2`, resolving facts LDAP cannot see:

- **Sessions (`HasSession`).** Enumerate logged-on sessions →
  `User -HasSession-> Computer`; volatile, stamped `Props["lastseen"]`, expiry
  candidate (§5.4).
- **Local groups (`AdminTo`).** Read local Administrators membership to derive
  `User/Group -AdminTo-> Computer` where `memberOf` omits local privilege.
- **Remote access.** SMB reachability alone implies neither `AdminTo` nor
  `CanPSRemote` (WinRM) nor `ExecuteDCOM` (DCOM); each needs its own probe.

SMB collection is heavier and noisier than LDAP, so it is gated behind
`Options.Sessions` / `Options.Method` and off in the default profile.

### 4.4 Sample collector (`sample.go`)

Emits a small, deterministic, hard-coded `model.Graph` (a hand-built domain with
users, groups, a computer, a GPO, and ACL edges). This lets `make run-sample`
start the API/UI with no AD or Neo4j and gives tests a stable `testdata/` fixture.

### 4.5 Full vs incremental collection

- **Full.** Walks the entire domain and produces a complete graph; ingestion
  treats a full run as authoritative for the categories it covers.
- **Incremental.** Runs a subset (sessions only, or objects changed since a
  `whenChanged` watermark) and emits a partial graph of the same shape;
  `Meta.Collector` plus a run category flag tell ingestion to merge, not replace.

### 4.6 CLI surface

```text
omenhound collect  [--domain FQDN] [--dc HOST] [--method ldap|smb|all]
                   [--user U] [--pass P | --hash NTHASH] [--full]
                   [--out graph.json] [--push http://host:8080]
omenhound serve    [--addr 127.0.0.1:8080] [--neo4j bolt://... | --memory]
                   [--collector sample] [--api-token TOKEN]
omenhound export   [--neo4j bolt://... | --memory] [--out graph.json]
omenhound version
```

`collect` writes JSON to `--out`/stdout and optionally pushes it to a running
`serve`. `export` reads a `Store` (`Snapshot`) back into a `model.Graph` for
offline analysis or format migration.

## 5. Graph Backend

### 5.1 Neo4j schema and BloodHound CE compatibility

OmenHound mirrors the BloodHound CE schema so CE Cypher works unmodified:

- **Labels.** Each node carries a common `:Base` label plus its kind label
  (`:User`, `:Group`, `:Computer`, `:Domain`, `:OU`, `:GPO`, `:Container`,
  `:Trust`); `:Base` lets generic queries span all entities.
- **Identity property.** `Node.ID` (the SID) is stored as **`objectid`**, the
  property BloodHound uses, so saved queries and path-finding join identically.
  `MERGE (n {objectid: $id})` is the upsert primitive.
- **Property mapping.** Each `Node` field projects to a property:

  | `model.Node` field | Neo4j property     | Notes               |
  |--------------------|--------------------|---------------------|
  | `ID`               | `objectid`         | merge key           |
  | `Kind`             | *(label)*          | `:Base` + `:<Kind>` |
  | `Name`             | `name`             |                     |
  | `Domain`           | `domain`           |                     |
  | `SAMAccountName`   | `samaccountname`   |                     |
  | `DN`               | `distinguishedname`|                     |
  | `Props[*]`         | same key           | whitelisted, typed  |

  `Props` keys are normalized to lowercase BloodHound spelling (`enabled`,
  `admincount`, `pwdlastset`, `lastlogon`, `hasspn`,
  `serviceprincipalnames`, `whencreated`) so arbitrary LDAP attribute casing
  never pollutes the schema.
- **Relationships.** `EdgeKind` is the relationship **type** verbatim, so
  `MATCH (u:User)-[:AdminTo]->(c:Computer)` behaves as in CE. `Edge.Props`
  (`inherited`, `isacl`, `lastseen`) become relationship properties.
- **Names to verify.** `GPLink` (our model) vs the exact CE spelling
  (`GpLink`/`GPLink`) and `TrustedBy` are validated per CE version by the
  compatibility test suite; the model value is source of truth in code.

### 5.2 Constraints and indexes

Applied idempotently at startup (or via `scripts/`):

```cypher
CREATE CONSTRAINT base_objectid_unique IF NOT EXISTS
FOR (n:Base) REQUIRE n.objectid IS UNIQUE;

CREATE INDEX base_name   IF NOT EXISTS FOR (n:Base) ON (n.name);
CREATE INDEX base_domain IF NOT EXISTS FOR (n:Base) ON (n.domain);
CREATE INDEX user_spn    IF NOT EXISTS FOR (n:User) ON (n.serviceprincipalnames);
```

The unique `:Base(objectid)` constraint enables safe concurrent `MERGE` upserts
and idempotent ingestion. Extra indexes serve search and UI typeahead;
relationship property indexes (`lastseen`) support expiry.

### 5.3 How the store persists a graph

`neo4j.go` batches writes in sized transactions using `UNWIND`:

```cypher
UNWIND $nodes AS n
MERGE (x:Base {objectid: n.objectid})
SET x += n.props
WITH x, n CALL apoc.create.addLabels(x, [n.label]) YIELD node RETURN count(node);
```

Where APOC is unavailable (the default assumption), the label is applied via
per-kind `UNWIND` batches instead. Edges are validated for endpoint existence:

```cypher
UNWIND $edges AS e
MATCH (s:Base {objectid: e.source}), (t:Base {objectid: e.target})
MERGE (s)-[r:TYPE]->(t)      // TYPE fixed per batch of a single EdgeKind
SET r += e.props;
```

Cypher cannot parameterize a relationship type, so edges are grouped by
`EdgeKind`, one statement template per kind. `memory.go` implements identical
semantics with Go maps and the same `Upsert*` contract, so tests run without a
database.

### 5.4 Rebuild vs incremental update, stale-edge expiry

- **Rebuild (full).** Merge everything, or run a scoped cleanup that deletes
  nodes/edges not touched in the run (`lastseen < run_start`) for the categories
  the run covers. Default: merge-on-write with optional post-ingestion cleanup.
- **Incremental.** Upsert only what arrived; never delete.
- **Stale-edge expiry.** Relationships written by a run get
  `Props["lastseen"] = run_start`. `Store.ExpireStaleEdges(olderThan)` deletes
  those not re-observed within a configurable window. Volatile edges need this
  most: `HasSession` is true only at collection time and gets a short TTL, while
  structural edges (`MemberOf`, `GenericAll`) get a long or infinite one. Each
  edge class carries a TTL policy so a stale session never masquerades as live.

## 6. Ingestion / API Service

### 6.1 Ingestion pipeline (`internal/ingest`)

`POST /api/v1/ingest` accepts a `model.Graph`, then:

1. **Authenticate** the caller (bearer token / API key, §6.4).
2. **Parse + size-limit** the body (streamed, bounded).
3. **Validate:** every node has `ID` + `Kind`; every edge references resolvable
   IDs and a known `EdgeKind`; `Meta` present. Invalid edges are dropped and
   counted (quarantine), not silently accepted.
4. **Normalize:** lowercase/normalize props, coerce timestamps, synthesize the
   SID-derived bits collection left implicit.
5. **Merge** through `Store.UpsertNodes` / `UpsertEdges` in batches.
6. **Record the run** (domain, collector, version, counts, duration) to the
   append-only JSONL audit log (`internal/audit`, records
   `{ts, actor, action, target, outcome, run_id, detail}`).
7. **Return** `{nodes_upserted, edges_upserted, edges_dropped, run_id}`.

The pipeline is the only HTTP-side writer to the `Store`; `export` uses
`Snapshot` and never mutates.

### 6.2 HTTP endpoints

| Method | Path                          | Purpose                                |
|--------|-------------------------------|----------------------------------------|
| GET    | `/api/v1/health`              | liveness + backend type                |
| GET    | `/api/v1/version`             | build metadata                         |
| POST   | `/api/v1/ingest`              | ingest a `model.Graph` (auth required) |
| GET    | `/api/v1/nodes/{id}`          | node by SID                            |
| GET    | `/api/v1/nodes?kind=&q=`      | search/list nodes                      |
| GET    | `/api/v1/edges?source=&kind=` | relationships of a node                |
| GET    | `/api/v1/paths?from=&to=`     | shortest attack path (edges)           |
| GET    | `/api/v1/abuse?edge=&from=`   | rendered abuse command(s) for an edge  |
| POST   | `/api/v1/creds/change`        | live credential change (gated, §6.6)   |
| GET    | `/api/v1/audit`               | recent audit records (auth required)   |
| GET    | `/` and `/assets/*`           | web UI (static bundle)                 |

Read queries are safe for an authenticated operator; the two privileged routes
are gated.

### 6.3 Abuse-command generation (`internal/abuse`)

Edge → template → interpolated command. Each `EdgeKind` has one or more
`abuse.Template` entries:

```go
type Template struct {
    Edge     model.EdgeKind
    Platform string   // "windows", "linux", "impacket"
    Command  string   // "net user {{.Target.SAMAccountName}} {{.Password}} /domain"
    OPSEC    OPSEC    // noise level + notes
}
```

At render time the service loads the **real** source/target nodes from the
`Store` and interpolates `{{.Source.*}}` / `{{.Target.*}}` from actual node
fields and `Props`. Nothing is hard-coded from the request: the command always
reflects the graph. Templates are data, not code — operators add or override them
via a config directory. `OPSEC` annotations flag loud commands (`ForceChangePassword`
is detectable, `DCSync` is high-signal) so the UI can warn before an operator
acts.

### 6.4 Authentication and authorization

- **API:** bearer token / API key via config, `--api-token`, or environment.
  Ingest and audit require it; reads require it by default (nothing anonymous
  unless explicitly configured).
- **UI:** session cookie after token exchange; same authorization gate.
- **Transport:** TLS in-process or via a fronting proxy; bind defaults to
  `127.0.0.1` so the service is not accidentally exposed.
- **Least privilege:** only `/ingest` writes graph data and only `/creds/change`
  can alter a live directory.

### 6.5 Credential handling (`internal/creds`)

Credentials are held **only in memory**. `internal/creds` provides a small vault
(put/get/zeroize) with a hard rule that no credential value is written to disk,
included in a `model.Graph`, logged, or returned by the API. Structs implement
redacting `String()`/`MarshalJSON()` so accidental logging prints `***`; process
exit best-effort zeroizes buffers. The API token and bind password are config/env
values, not persisted state.

### 6.6 Live credential-change feature (gated)

The single capability that changes the target environment. Guardrails are
cumulative — all must hold:

1. **Opt-in:** disabled unless explicitly enabled in config.
2. **Lab-gated:** refuses unless the target domain matches a configured lab
   allow-list.
3. **Approval-gated:** requires a second, out-of-band approval token per action.
4. **Audit-logged:** every attempt (success or failure) recorded before/after.
5. **Least action:** exactly one documented change, no chaining.

If any gate fails the request is rejected and audited. The default build ships
with the feature off.

## 7. UI Strategy

Two-stage, with an explicit fallback:

1. **Customized BloodHound CE UI (primary).** Start from the CE UI's static
   templates/assets and progressively make the static parts dynamic: templates
   that hard-code endpoints or schema strings are templated from OmenHound's
   `/api/v1/*` API and served by the Go service — CE's familiar attack-path
   explorer backed by OmenHound's API and abuse renderer, not a rewrite.
2. **Stock CE UI (fallback).** If template surgery breaks on a CE version bump,
   serve the unmodified CE static bundle against an OmenHound-populated Neo4j
   with the CE-compatible schema (§5). Because labels, edge names, and `objectid`
   already match, it keeps working unchanged — which is why CE compatibility is a
   hard requirement.

Serving: the Go service serves `web/` (dev: from source with a proxy; prod: the
gitignored `web/dist`). The UI is a static bundle plus OmenHound API calls; no
server-side rendering dependency.

## 8. Repository Layout and Build Order

### 8.1 Layout

```text
omenhound/
├── cmd/omenhound/            # main; subcommands (collect|import|serve|export|version)
├── internal/
│   ├── collector/            # Collector interface + ldap.go, smb.go, sample.go, methods.go
│   ├── bloodhound/           # BloodHound CE JSON/zip import + export
│   ├── graph/                # Store interface + memory.go, neo4j.go
│   ├── ingest/               # pipeline: strict decode, validate + merge
│   ├── api/                  # HTTP handlers, routing, auth/rate-limit middleware
│   ├── abuse/                # edge -> template -> rendered command + OPSEC
│   ├── creds/                # memory-only credential vault (redacting types)
│   ├── audit/                # append-only JSONL audit log
│   ├── act/                  # the only AD write path (unicodePwd over LDAPS)
│   └── version/              # version.Version, set via -ldflags
├── pkg/model/                # model.go — the shared data contract (public)
├── web/static/               # embedded UI (index.html, app.js, styles.css)
├── wiki/                     # wiki-source docs (Home.md, …) + img/ screenshots
├── scripts/  testdata/ docs/ # helpers; fixtures; design docs
├── Makefile · go.mod         # build targets; module github.com/.../omenhound
```

`pkg/model` is deliberately public (`pkg/`, not `internal/`) so external
collectors and plugins can import the contract. Everything else is `internal/`,
keeping the public API surface to exactly one package.

### 8.2 Build order / phases

- **Phase 0 — Scaffold (done).** `go.mod`, `Makefile`, `.gitignore`, LICENSE,
  `internal/version`, `pkg/model/model.go` (the full data model).
- **Phase 1 — Skeleton pipeline.** `Collector` + `sample.go`; `Store` +
  `memory.go`; the CLI with all four subcommands and `export`. Deliverable:
  `make run-sample` works end to end with no AD and no Neo4j.
- **Phase 2 — Ingestion + API.** `internal/ingest` validation/merge and
  `internal/api` read + ingest endpoints with auth. Deliverable: push a sample
  graph over HTTP and query it back.
- **Phase 3 — Neo4j backend.** `neo4j.go` + constraints/indexes; verify CE
  queries run against a populated DB. Deliverable: CE compatibility smoke test.
- **Phase 4 — LDAP + SMB collection.** `ldap.go` (users/groups/computers/OUs/
  GPOs/ACLs/membership/trusts, paging, primary-group synthesis) and `smb.go`
  (sessions, local admin, remote-access edges, TTL/expiry wiring).
- **Phase 5 — Abuse renderer.** `internal/abuse` templates + OPSEC, wired to
  `/api/v1/abuse`.
- **Phase 6 — UI.** Customize CE templates to the dynamic OmenHound API; keep
  the stock-CE fallback green.
- **Phase 7 — Gated capabilities.** `internal/creds` vault, `internal/audit`,
  and the opt-in/lab/approval-gated live credential change.
- **Phase 8 — Interop + hardening (done).** `internal/bloodhound` CE v5 import and
  `--zip` export; BloodHound.py-compatible collect flags with method planning and
  SRV DC discovery; graph/API optimization (O(1) dedup, adjacency, batched
  `UNWIND`, rate limits, pagination, security headers); token-gated write API in
  the embedded UI.

**Cadence:** `make all` = `vet test build`; `make run-sample` for the
zero-dependency demo; `go test ./...` must pass with only the memory store.

## 9. Extension Points and Roadmap

**Extension points (stable by design):**

- **New collectors.** Implement `Collector` and register a subcommand/method.
  Because the contract is `model.Graph`, RPC/DCOM, Entra ID, or a third-party
  collector can be added without touching the store or API.
- **New store backends.** Implement `Store` (embedded graph, read-replica,
  sharded backend); ingestion, API, and export are store-agnostic.
- **New edge kinds.** Add an `EdgeKind` constant in `pkg/model`, a write mapping
  in the store, and abuse templates. No API change required.
- **Abuse templates as data.** Operators extend/override templates and OPSEC
  notes from a config directory without rebuilding.
- **UI adapters.** The UI talks only to `/api/v1/*`, so it can be swapped or
  extended independently; the stock CE fallback remains supported.

**Roadmap themes:**

- **RPC/DCOM collection** (`ExecuteDCOM`, richer remote-access edges) with native
  Go RPC over SMB, avoiding Python/Impacket on the collector host.
- **Streaming for large domains.** NDJSON archive transport with the same
  `model.Graph` semantics, plus resumable incremental pushes.
- **Entra ID / hybrid.** New node kinds (`AZTenant`, `AZUser`, `AZGroup`,
  `AZServicePrincipal`, `AZApp`) and edges following CE's Azure model, without
  disturbing the AD model.
- **Scheduling, diffing, scale.** Collection schedules, run-to-run diffs,
  alert-on-new-path, and Neo4j driver/batching tuning for very large forests.

**Design invariants to preserve:**

1. SIDs (or objectGUID) are the identity key; names are payload.
2. `model.Graph` JSON is the only contract; CE schema compatibility keeps the
   stock CE UI and CE queries a working fallback.
3. Credentials are memory-only, the audit log is append-only, and any capability
   that changes the target environment is opt-in, gated, and logged.
