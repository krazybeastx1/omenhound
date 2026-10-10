# Web UI Guide

The UI is served by `omenhound serve` at `http://<addr>/`. It is a dependency-free
canvas force graph embedded in the binary — no npm, no bundler, no CDN.

```bash
./bin/omenhound serve --collector sample --addr 127.0.0.1:8080
# open http://127.0.0.1:8080
```

## The attack-path graph

![OmenHound graph view](img/webui-graph.png)

- **Nodes** are coloured by kind (`User`, `Group`, `Computer`, `Domain`, `GPO`, `OU`,
  `Container`, `Trust`); the legend is shown in the empty panel.
- **Edges** are AD relationships. Node labels show `name / sAMAccountName / SID`.
- **Drag** to pan, **scroll** to zoom, **drag a node** to move it.
- The top bar shows `N nodes · M edges`.

## Inspecting a node

Click a node to open the node inspector:

- `kind`, `sid`, `sam`, `domain`, `dn`, plus every collected property.
- **Outgoing** and **Incoming** edge lists — click any entry to jump to that edge's
  abuse panel.

## Abuse panel (per edge)

Click an **edge** (or an entry in the node's edge list) to open the abuse panel. This is
the heart of OmenHound: the command is generated at render time from **your** graph's
real properties.

![OmenHound abuse panel](img/webui-abuse.png)

The panel shows:

| Section | Contents |
|---|---|
| **title / summary** | the edge kind and `source → target` |
| **Command** | a copy-pasteable primary command with real SAM/DN/domain/DC |
| **Alternates** | alternative tooling (impacket, certipy, SharpGPOAbuse, …) |
| **OPSEC** | what the action looks like on the wire / in logs |
| **Event IDs** | Windows event IDs to correlate |
| **⚠ warnings** | emitted whenever a needed property is missing — never a silent gap |

The same rendering is available over HTTP:

```bash
curl -s "http://127.0.0.1:8080/api/v1/abuse?src=<SID>&kind=GenericAll&dst=<SID>" | jq
curl -s "http://127.0.0.1:8080/api/v1/abuse/supported" | jq
```

## Search

Type in the top bar to filter by **name, sAMAccountName, or SID**. Non-matching nodes
are dimmed in place, so you keep the surrounding topology.

## Reload

**Reload** re-fetches `/api/v1/graph` (useful after an ingest) and refreshes the footer
health line: `v<version> · credential-ops ON/off · write-api ON/off`.

## Write-API auth gate

The UI is **read-only by default**. Graph-modifying endpoints require an operator bearer
token, so the UI exposes a gated **Write API** control (top right). Clicking it opens the
auth gate:

![OmenHound write-API auth gate](img/webui-authgate.png)

- The token is held in **this tab's memory only** and never persisted.
- The gate submits to `POST /api/v1/ingest` with `Authorization: Bearer <token>`.
- A bad/absent token surfaces the **real** server response — the screenshot above shows
  `denied: unauthorized`, which is the actual `401` from the server, not a mock.
- On success the control flips to 🔓 and the graph reloads.

> The gate is a convenience wrapper over the same bearer-token auth the CLI and `curl`
> use. It does not weaken the server-side checks: the token is still required and
> constant-time compared, and every write is audited.

## Screenshot capture (for maintainers)

`scripts/shots.py` regenerates the images above using Selenium + the system Chromium:

```bash
./bin/omenhound serve --collector sample --addr 127.0.0.1:18091 --api-token operator-secret &
python3 scripts/shots.py http://127.0.0.1:18091 docs/wiki/img
```

It captures the graph, performs a **real edge click** for the abuse panel, and drives the
auth gate with a bad token so the `denied` state is genuine.

Next: **[Operations & Hardening](Operations-and-Hardening)** →
