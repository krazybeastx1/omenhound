# Operations & Hardening

OmenHound handles live credentials and can act on Active Directory, so it treats itself
as a high-value target. This page is the operator-facing summary; the full analysis lives
in [`docs/THREAT-MODEL.md`](https://github.com/krazybeastx1/omenhound/blob/main/docs/THREAT-MODEL.md).

## Secure defaults

| Control | Default | How to change |
|---|---|---|
| Plaintext LDAP collection | **refused** | `--allow-plaintext-ldap` (lab only) |
| AD writes (`unicodePwd`) | **disabled** | `--enable-credential-ops` |
| Write API (ingest/credentials) | **disabled** | `--api-token <secret>` |
| Write rate limit | 120/min, burst 30 | `--write-rate-limit`, `--write-burst` |
| Listen address | `127.0.0.1:8080` | `--addr` |
| TLS verification | **on** | `--insecure` (lab only, loudly warned) |

## Credential handling

- Secrets are held as `[]byte`, never written to disk, and explicitly zeroed after use
  (`creds.Zero`, with `runtime.KeepAlive` to defeat dead-store elimination). The caller's
  buffer is copied, never aliased.
- The session credential store is **memory-only, TTL-scoped** (15 min) and capped
  (64 entries, max 4096 bytes per secret); a background **janitor** sweeps expired
  entries.
- The audit logger **redacts** any field whose name matches
  `password` / `secret` / `token` / `hash` / … before writing.
- Prefer `--password-stdin` or `$OMENHOUND_PASSWORD` over `--password`, which is visible
  in process listings.

## Transport security

- Collection uses **LDAPS** (636). AD writes **refuse to run without an encrypted
  channel** — `internal/act` returns `ErrLDAPSRequired` and dials `ldaps://` with a
  minimum of TLS 1.2.
- `--ldap-channel-binding` is accepted for BloodHound.py parity but is a **no-op** for LDAP
  simple bind over TLS (channel binding applies to NTLM/Kerberos). OmenHound tells you so
  rather than silently ignoring the flag.

## Access control for the API

Every write endpoint enforces a bearer token with a **constant-time comparison**.

```
POST   /api/v1/ingest                   (merge by default; ?mode=replace clears first)
DELETE /api/v1/graph                    (confirmation required: ?confirm=true)
POST   /api/v1/credentials
DELETE /api/v1/credentials/{id}
POST   /api/v1/credentials/{id}/change-password
```

- If `--api-token` is empty, writes return **403 "write API is disabled"**.
- A bad/missing token returns **401 unauthorized** and is audited as a denied auth event.
- `DELETE /api/v1/graph` is destructive, so it also requires `?confirm=true`; a bare delete
  is refused with **400**. In `--neo4j-uri` mode it clears the whole configured database.
- The password-change endpoint has an **additional per-action approval gate**: it requires
  the header `X-Omenhound-Approval: yes`. Without it, the request is refused with
  **428 Precondition Required** and audited as denied.

### Gated password change — full flow

```bash
# 1) start the server with credential ops enabled (authorized lab only)
export OMENHOUND_API_TOKEN="$(openssl rand -hex 32)"
./bin/omenhound serve --collector none --addr 127.0.0.1:8080 \
  --api-token "$OMENHOUND_API_TOKEN" \
  --enable-credential-ops \
  --act-server dc01.corp.local \
  --audit-log /var/log/omenhound/audit.jsonl

# 2) stage the credential (one-shot; TTL-scoped, memory only)
curl -sS -X POST http://127.0.0.1:8080/api/v1/credentials \
  -H "Authorization: Bearer $OMENHOUND_API_TOKEN" \
  -d '{"domain":"corp.local","username":"svc","password":"..."}'
# -> {"session_id":"...","expires":"..."}

# 3) change the target's password — requires explicit approval
curl -sS -X POST http://127.0.0.1:8080/api/v1/credentials/<session_id>/change-password \
  -H "Authorization: Bearer $OMENHOUND_API_TOKEN" \
  -H "X-Omenhound-Approval: yes" \
  -d '{"target_dn":"CN=Jane,OU=Users,DC=corp,DC=local","target_sid":"S-1-5-...","new_password":"...","reason":"TICKET-123"}'
```

The staged credential is **taken (one-shot)** by the change operation and destroyed
afterwards.

## Audit

Every write and auth decision is written as a JSON line with actor, action, target,
result, reason, remote address, and selected fields. Steer it to a file with
`--audit-log`; otherwise it goes to stderr.

```json
{"time":"...","actor":"api","action":"credential.change_password","target":"CN=Jane,...",
 "result":"ok","reason":"TICKET-123","remote_addr":"127.0.0.1:51234","fields":{"target_sid":"S-1-5-..."}}
```

## Network posture

- The server binds to **loopback by default**. If you expose it, put it behind a TLS
  reverse proxy and keep the bearer token secret.
- The API sets `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and emits
  `Strict-Transport-Security` when serving over TLS.
- A per-IP token-bucket limiter protects all endpoints; writes have their own limiter.
  The client IP is derived from the socket and **ignores `X-Forwarded-For`** to avoid
  spoofed-limit bypass.

## Operator OPSEC

OmenHound's abuse templates include per-technique OPSEC and event IDs. In general:

- LDAP enumeration is **read-only** but noisy under advanced audit policy (4662 for
  object reads, 1644 with expensive/LDAP diagnostics).
- Password resets hit **4724**; ACL writes hit **5136/5137**; replication hits **4662**;
  Kerberos abuse shows in **4768/4769**.
- Pace collection (`--timeout`, method selection) and prefer DCOnly-style minimal
  collection when you only need paths.

## Rules of engagement checklist

1. Written authorization, scope, and a defined time window.
2. Dedicated, least-privilege bind account; rotate it after.
3. LDAPS only; never `--allow-plaintext-ldap` outside a lab.
4. Keep credential ops **off** unless you intend to change passwords, and use the
   approval header deliberately.
5. Ship the audit log to a system you don't control.
6. Clean up: delete staged credentials, revert any AD changes, report findings.

Next: **[API Reference](API-Reference)** →
