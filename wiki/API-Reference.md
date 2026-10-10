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
  "props": { "enabled": "true", "admincount": "1" }
}
```

`kind` ∈ `User | Group | Computer | Domain | OU | GPO | Container | Trust | Base`.

### Edge

```json
{ "source": "S-1-5-...-1103", "target": "S-1-5-...-512", "kind": "GenericAll",
  "props": { "inherited": "true" } }
```

### Graph

```json
{ "nodes": [ /* Node */ ], "edges": [ /* Edge */ ],
  "meta": { "collector": "ldap", "version": "…", "domain": "…",
            "started_at": "…", "finished_at": "…", "warnings": ["…"] } }
```

---

## Read endpoints (no auth)

### `GET /api/v1/health`

```json
{ "status": "ok", "version": "f7e8055", "credential_ops_enabled": false,
  "write_api_enabled": true, "time": "2026-10-10T12:18:03Z" }
```

### `GET /api/v1/stats`

```json
{ "nodes": 1284, "edges": 3610 }
```

### `GET /api/v1/graph`

Returns the entire graph as a `Graph` object (see above). This is what the UI loads.

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

Renders the dynamic abuse instruction for a concrete edge.

```json
{
  "edge": { "source": "S-1-5-...-1103", "target": "S-1-5-...-512", "kind": "GenericAll" },
  "source": { /* Node */ },
  "target": { /* Node */ },
  "summary": "Full control over the target object …",
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

---

## Write endpoints (bearer token required)

All write endpoints require `Authorization: Bearer <token>`. With no `--api-token`
configured they return `403 write API is disabled`. A wrong token returns
`401 unauthorized` and is audited as a denied auth event.

### `POST /api/v1/ingest`

Body: a `Graph` object. Size-bounded to 512 MiB, unknown JSON fields rejected, and the
graph is validated (vocabulary, referential integrity, size) before it touches the store.
`Content-Type: application/json`.

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/ingest \
  -H "Authorization: Bearer $OMENHOUND_API_TOKEN" \
  --data-binary @graph.json
```

```json
{ "nodes": 13, "edges": 14, "stats": { "nodes": 13, "edges": 14 } }
```

Errors: `400` invalid/oversized/invalid graph, `401` unauthorized, `403` disabled.

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
