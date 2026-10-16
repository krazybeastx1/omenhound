# API Reference

Base URL is whatever you pass to `serve --addr` (default `http://127.0.0.1:8080`).
All request/response bodies are JSON. Write endpoints require
`Authorization: Bearer <token>` and are fully audited.

## Data shapes

### Node

```json
{
  "id": "S-1-5-21-1004336348-1177238915-682003330-1103",
  "kind": "User",
  "name": "JDOE",
  "domain": "omenhound.lab",
  "sam_account_name": "jdoe",
  "distinguished_name": "CN=JDOE,OU=Users,DC=omenhound,DC=lab",
  "props": { "enabled": "true", "admincount": "1" },
  "sources": ["ldap"],
  "batches": ["batch_20261016T071035.123_a1b2c3d4e5"]
}
```

`sources` and `batches` are present when the store tracks ingestion provenance (in-memory store).

### Edge

```json
{ "source": "S-1-5-...-1103", "target": "S-1-5-...-512", "kind": "GenericAll",
  "props": { "inherited": "true" },
  "sources": ["bloodhound-import"],
  "batches": ["batch_20261016T071035.456_f7e8055120"] }
```

### Graph

```json
{
  "nodes": [ /* Node */ ],
  "edges": [ /* Edge */ ],
  "meta": {
    "collector": "ldap",
    "version": "4.1.01-omenhound",
    "domain": "omenhound.lab",
    "started_at": "...",
    "finished_at": "...",
    "warnings": ["..."]
  },
  "sources": [
    { "name": "ldap", "nodes": 106, "edges": 32 }
  ],
  "datasets": [
    { "id": "batch_20261016T071035.123_a1b2c3d4e5", "source": "ldap", "domain": "omenhound.lab",
      "mode": "merge", "status": "completed", "created_at": "...",
      "nodes_created": 106, "edges_created": 32 }
  ]
}
```

---

## Read endpoints (no auth)

### `GET /api/v1/health`

```json
{ "status": "ok", "version": "4.1.01-omenhound", "credential_ops_enabled": false,
  "write_api_enabled": true, "time": "2026-10-10T12:18:03Z" }
```

### `GET /api/v1/stats`

```json
{ "nodes": 1284, "edges": 3610 }
```

### `GET /api/v1/graph`

Returns the entire graph as a `Graph` object (see above). This is what the UI loads. When provenance tracking is
available (in-memory store), every node and edge include `sources` and `batches`, and the response adds
`sources` (per-collection counts) and `datasets` (ingestion batches).

### `GET /api/v1/nodes?limit=&offset=`

Paginated node list. `limit` default **1000**, max **10000**; `offset` default 0.

```json
{ "total": 1284, "limit": 1000, "offset": 0, "nodes": [ /* Node */ ] }
```

### `GET /api/v1/edges?limit=&offset=`

Same shape for edges:

```json
{ "total": 3610, "limit": 1000, "offset": 0, "edges": [ /* Edge */ ] }
```

### `GET /api/v1/nodes/{id}`

Returns a single `Node`, or `404 {"error":"node not found"}`.

### `GET /api/v1/nodes/{id}/neighbors`

```json
{ "outgoing": [ /* Edge */ ], "incoming": [ /* Edge */ ] }
```

### `GET /api/v1/abuse?src=<SID>&kind=<EdgeKind>&dst=<SID>`

Renders the dynamic abuse instruction for a concrete edge. The `read` field is the
verify/enumerate step, `command` the act step (labeled **Read** / **Add** in the UI);
both are interpolated from the two nodes' real properties, and missing values become
`<unknown>` plus a `warnings[]` entry.

```json
{
  "edge": { "source": "S-1-5-...-1103", "target": "S-1-5-...-512", "kind": "GenericAll" },
  "source": { /* Node */ },
  "target": { /* Node */ },
  "summary": "Full control over the target object …",
  "read": "impacket-dacledit -action read -target-dn CN=jdoe,OU=Users,DC=omenhound,DC=lab 'omenhound.lab/jdoe:<password>'",
  "command": "bloodyAD --host dc01.omenhound.lab -d omenhound.lab -u jdoe -p '<password>' set password 'Domain Admins' 'NewPassw0rd!42'",
  "alternates": ["impacket-dacledit …"],
  "opsec": "unicodePwd over LDAPS (4724) …",
  "event_ids": [4724, 5136],
  "warnings": ["target has no samaccountname"]
}
```

Errors: `400` if any of `src`/`kind`/`dst` is missing, `404` if a node or template is
not found.

### `GET /api/v1/abuse/supported`

```json
{ "edges": ["GenericAll", "WriteDacl", "MemberOf", "AdminTo", "…"] }
```

### `GET /api/v1/abuse/playbook`

The grouped, edge-agnostic **technique library** — 10 categories / 54 techniques
(33 edge-backed + 21 standalone). Commands keep their `{PLACEHOLDER}` tokens and are
reference material only; read-only. See [Technique Library](Technique-Library) for
the full walkthrough.

```json
{ "categories": [ {
  "id": "acl", "title": "Access control (ACL)", "note": "These are graph edges…",
  "techniques": [ {
    "id": "GenericAll", "title": "Full control over the object", "edge": "GenericAll",
    "summary": "Full control over the target object …",
    "read": "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
    "command": "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set password {TARGET_SAM} 'NewPassw0rd!42'",
    "alternates": ["impacket-dacledit …"],
    "opsec": "unicodePwd over LDAPS (4724) …",
    "event_ids": [4724, 5136],
    "requires": "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
    "tags": ["acl", "write"]
  } ]
} ] }
```

### `POST /api/v1/paths/shortest`  ·  `GET /api/v1/paths/shortest`

Shortest routes between a source and a target. `POST` takes the request as JSON;
`GET` takes the same fields as query parameters (`from`, `to`, `direction`,
`max_depth`, `max_paths`). Read-only — the graph is never modified.

```json
{
  "source_id": "S-1-5-21-…-1103",
  "target_id": "S-1-5-21-…-512",
  "direction": "outgoing",
  "max_depth": 6,
  "max_paths": 10,
  "include_node_types": ["User", "Group"],
  "exclude_node_types": [],
  "include_relationship_types": ["MemberOf", "GenericAll"],
  "exclude_relationship_types": [],
  "include_domains": ["corp.local"],
  "exclude_domains": [],
  "alternative": false,
  "required_intermediate_node_ids": []
}
```

| Field | Notes |
|---|---|
| `direction` | `outgoing` (default), `incoming` or `undirected`. |
| `max_depth` | Hop limit (default 6). |
| `max_paths` | Cap on returned routes (default 10, hard cap 100). |
| `include_/exclude_*` | Optional allow/deny lists for node kinds and relationship kinds. |
| `include_domains` / `exclude_domains` | Restrict traversal to nodes in (or not in) the listed domains. The source node is exempt so a scoped search can still run; the target is filtered like any other node. |
| `alternative` | `false` (default) returns only minimum-hop routes; `true` also enumerates longer **simple** routes in increasing length order (bounded by `max_paths`, `max_depth` and the backend expansion budget). |
| `required_intermediate_node_ids` | Routes must pass through every listed node. |

```json
{
  "paths": [
    {
      "nodes": [{"id": "S-1-…", "kind": "User", "name": "jdoe"}, {}],
      "relationships": [{"source": "S-1-…", "target": "S-2-…", "kind": "MemberOf"}],
      "length": 1
    }
  ],
  "truncated": false
}
```

The search returns up to `max_paths` **distinct shortest routes of equal length** —
not every possible route. With `alternative: true` the same walk continues past the
minimum hop count to enumerate longer **simple** routes, still in increasing length order;
the caller can label the first (shortest) routes apart from the rest. Relationships are
always returned in their **stored** orientation (`source → target`), even for
`incoming`/`undirected` traversal, so a caller can match them against the dataset.
`truncated` is `true` when a search limit (max paths, or the backend's expansion budget)
stopped the walk early.

### `GET /api/v1/analytics`

Lists the canned attack-path queries.

```json
{
  "queries": [
    {
      "id": "kerberoastable",
      "title": "Kerberoastable users",
      "category": "Credentials",
      "description": "Enabled users with a service principal name (SPN)…",
      "cypher": "MATCH (u:User) WHERE NOT u.name STARTS WITH 'KRBTGT' AND (u.hasspn = true OR u.serviceprincipalname IS NOT NULL) RETURN u"
    }
  ]
}
```

The `cypher` field is the equivalent BloodHound CE query, so the same question can
be run against a CE-populated Neo4j graph.

### `GET /api/v1/analytics/{id}`

Runs one canned query against the current graph. `{id}` is any id from the list
above — for example `kerberoastable`, `asreproastable`, `dcsync`,
`laps-readable`, `unconstrained-delegation`, `constrained-delegation`, `rbcd`,
`adminto`, `has-session`, `high-value-targets`, `admincount`, `sensitive-users`,
`owned`, `password-never-expires`.

```json
{
  "query": { "id": "dcsync", "title": "DCSync-capable principals", "category": "Credentials" },
  "count": 1,
  "findings": [
    {
      "node": { "id": "S-1-5-...-1103", "kind": "User", "name": "REPLADMIN" },
      "reason": "Holds directory replication rights; can replicate credential hashes from the domain.",
      "evidence": ["GetChangesAll → UXLAB"],
      "related": ["S-1-5-21-9"]
    }
  ],
  "notes": []
}
```

`notes` is where honesty lives: if the graph contains no node carrying the
attribute (or no relationship of the kind) that a query depends on, the note says
so, so a `count` of `0` is never presented as a clean bill of health. Errors:
`404` for an unknown query id.

---

## Write endpoints (bearer token required)

All write endpoints require `Authorization: Bearer <token>`. With no `--api-token`
configured they return `403 write API is disabled`. A wrong token returns
`401 unauthorized` and is audited as a denied auth event.

### `POST /api/v1/ingest`

Body: a `Graph` object. Size-bounded to 512 MiB, unknown JSON fields rejected, and the
graph is validated (vocabulary, referential integrity, size) before it touches the store.
`Content-Type: application/json`.

Query parameters:

| Parameter | Behaviour |
|---|---|
| `mode` | `merge` (default) or `replace`. An unknown value is a `400`, never guessed. |
| `domain` | Restrict the import to one domain. Entities that declare a **different** domain are rejected (or skipped, see `on_mismatch`); the file is *not* assumed to belong to the selected domain. |
| `on_mismatch` | `reject` (default) or `skip`: what to do with entities whose own domain differs from `domain`. |
| `unknown` | `keep` (default) or `stamp`. `stamp` assigns `domain` to entities that carry no domain of their own; the default leaves them unassigned and rejects them. |
| `source` | Free-form provenance label (usually the filename), recorded on the batch. |

Without `domain` the historical behaviour is kept: every domain present in the file is
imported as-is. A scoped import **never** silently defaults to "all domains".

```bash
# merge (default) — import everything in the file
curl -sS -X POST http://127.0.0.1:8080/api/v1/ingest \
  -H "Authorization: Bearer $OMENHOUND_API_TOKEN" \
  --data-binary @graph.json

# import only the corp.local objects, rejecting anything else
curl -sS -X POST "http://127.0.0.1:8080/api/v1/ingest?domain=corp.local&on_mismatch=reject&source=corp.json" \
  -H "Authorization: Bearer $OMENHOUND_API_TOKEN" \
  --data-binary @graph.json

# replace everything with this graph
curl -sS -X POST "http://127.0.0.1:8080/api/v1/ingest?mode=replace" \
  -H "Authorization: Bearer $OMENHOUND_API_TOKEN" \
  --data-binary @graph.json
```

```json
{
  "nodes": 13, "edges": 14,
  "stats": { "nodes": 13, "edges": 14 },
  "tracked": true,
  "batch": { "id": "batch_20261013T134707.747_c4e579dc78", "domain": "corp.local", "status": "completed" }
}
```

`tracked` is `true` when the store records ingestion provenance (the in-memory store does).
`mode=replace` with a `domain` clears **only that domain** first, so other domains survive.

Errors: `400` invalid/oversized/invalid graph, unknown mode, or a domain mismatch under
`on_mismatch=reject`; `401` unauthorized; `403` disabled.

### `POST /api/v1/ingest/preview`

Dry run: validate an upload against a scope with the same `domain`, `on_mismatch` and
`unknown` parameters and return what *would* be written. Nothing is stored.

```json
{
  "preview": {
    "domain": "corp.local",
    "domains": ["corp.local"],
    "nodes": 13, "edges": 14,
    "assigned_nodes": 13, "stamped_nodes": 0,
    "mismatch_nodes": 0, "skipped_nodes": 0, "skipped_edges": 0,
    "cross_domain_edges": 0
  }
}
```

A domain mismatch under `on_mismatch=reject` returns `422` with the same `preview` plus an
`error` string, so the UI can show exactly which objects would be refused.

### `GET /api/v1/ingest/batches`

Ingestion history, newest first. Each batch carries its `id`, `source`, `domain`,
`domains`, `mode`, `status` (`completed` / `partial` / `failed`), created/updated counters,
skipped counts and any errors. A batch id is provenance metadata, **not** an AD identity.

### `GET /api/v1/ingest/batches/{id}`

One batch's metadata. `404` if unknown.

### `POST /api/v1/ingest/batches/{id}/delete-preview`

Compute the impact of deleting everything a batch introduced, without deleting anything.
The response is a `DeletionPreview`:

```json
{
  "scope": "batch", "target": "batch_…",
  "delete_nodes": 13, "delete_edges": 14,
  "preserved_nodes": 0, "preserved_edges": 0,
  "shared_nodes": 0, "legacy_nodes": 0,
  "warnings": [],
  "token": "sha256:…"
}
```

Records that another import also needs (`shared_nodes`) are **preserved**; relationships
incident to a deleted node are always removed (the model forbids dangling edges) and any
forced removal is reported in `warnings`. `token` fingerprints the exact plan.

### `DELETE /api/v1/ingest/batches/{id}`

Delete a batch's data. Requires `?confirm=true` and the `token` from a fresh preview;
if the graph changed since the preview the request is rejected with `409` and a new
preview is required. Returns a `DeletionResult` (`deleted_nodes`, `deleted_edges`,
`preserved_nodes`, `preserved_edges`, `batch_removed`).

### `GET /api/v1/ingest/domains`

Ingested domains with their node/edge/batch counts.

### `POST /api/v1/ingest/domains/{domain}/delete-preview`  ·  `DELETE /api/v1/ingest/domains/{domain}`

Same preview-then-confirm workflow scoped to a whole domain. `DELETE` requires
`?confirm=true` plus the preview `token`. Only that domain's records are removed; records
shared with another domain's import are preserved, and dependent relationships are
reported before anything is committed.

### `POST /api/v1/ingest/records/delete-preview`  ·  `POST /api/v1/ingest/records/delete`

Preview and delete an explicit selection *within* a scope (a batch or a domain):

```json
{ "scope": "domain", "target": "corp.local",
  "node_ids": ["S-1-5-21-…-1103"], "edge_keys": ["S-1-…\u0000MemberOf\u0000S-2-…"] }
```

The backend validates every id against the scope and refuses ids that are not part of it,
so a crafted request cannot delete outside the labelled scope.

> **Scoped deletion needs provenance.** These endpoints work on any store that implements
> the `IngestManager` contract (the default in-memory store does). A store that cannot
> track provenance returns `501` with a clear message rather than performing an unscoped
> delete. The Neo4j backend currently does **not** implement provenance, so scoped deletion
> is unavailable there; use it with the in-memory store, or clear the whole database with
> `DELETE /api/v1/graph` on a database dedicated to OmenHound.

### `DELETE /api/v1/graph`


Delete every node and relationship the server currently holds. The write token is
required, and a bare `DELETE` is refused: re-send with `?confirm=true` (accepted values
`true`, `yes`, `1`) so a stray request cannot wipe the graph by accident.

```bash
curl -sS -X DELETE "http://127.0.0.1:8080/api/v1/graph?confirm=true" \
  -H "Authorization: Bearer $OMENHOUND_API_TOKEN"
```

```json
{ "cleared": true, "stats": { "nodes": 0, "edges": 0 } }
```

Errors: `400` missing confirmation, `401` unauthorized, `403` disabled.

> With `--neo4j-uri` the store treats the configured database as *the* graph, so this
> clears the whole database (all nodes). Point `--neo4j-db` at a database dedicated to
> OmenHound before using either the delete endpoint or `mode=replace`.

### `POST /api/v1/credentials`

Stage a bind credential for a later credential-op. Requires `--enable-credential-ops`.

```json
{ "domain": "corp.local", "username": "svc", "password": "…" }
```

`201 Created`:

```json
{ "session_id": "…", "expires": "2026-10-10T12:33:03Z" }
```

The credential is memory-only, TTL-scoped, and never returned again.

### `DELETE /api/v1/credentials/{id}`

```json
{ "deleted": "…" }
```

### `POST /api/v1/credentials/{id}/change-password`

Requires `--enable-credential-ops` **and** the header `X-Omenhound-Approval: yes`
(otherwise `428 Precondition Required`, audited as denied). The staged credential is
**taken (one-shot)** and destroyed.

```json
{ "target_dn": "CN=Jane,OU=Users,DC=corp,DC=local",
  "target_sid": "S-1-5-21-…-1103",
  "new_password": "…",
  "reason": "TICKET-123" }
```

`200 OK`:

```json
{ "changed": "CN=Jane,OU=Users,DC=corp,DC=local", "target_sid": "S-1-5-21-…-1103" }
```

Errors: `403` credential ops disabled, `404` unknown session id, `502` AD write failed,
`428` missing approval header.

---

## Error format

All errors are `{"error": "<message>"}` with a matching HTTP status.

## Rate limiting

A per-IP token bucket applies to all requests; writes have a separate bucket
(`--write-rate-limit`, `--write-burst`). Exceeding it returns `429`. The client IP is
taken from the socket and **ignores `X-Forwarded-For`**.

Next: **[Neo4j Schema & Attack Paths](Neo4j-Schema-and-Attack-Paths)** →
