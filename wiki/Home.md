# OmenHound

**A BloodHound-style Active Directory attack-path tool, rewritten from scratch in Go.**

OmenHound collects AD objects over LDAP/LDAPS, stores them in a graph that uses the
**BloodHound CE schema** (Neo4j), renders **dynamic abuse commands with OPSEC notes**
for every edge, and serves a dependency-free web UI — all from a single static binary.

```
collector ──Graph JSON──▶ ingest ──▶ Store ──▶ Neo4j (BloodHound CE schema)
(ldap/sample)                         │
                                      └──▶ API ──▶ Web UI (canvas attack-path graph)
                                              └──▶ abuse engine (edge → command + OPSEC)
```

> [!WARNING]
> OmenHound is **dual-use offensive security tooling**. It enumerates Active Directory,
> maps attack paths to Domain Admin, and *optionally* changes AD account passwords over
> LDAPS. Use it **only** against systems you own or have explicit written authorization
> to test. Unauthorized use is illegal.

---

## Start here

| If you want to… | Read |
|---|---|
| Install it and see something work in 60 seconds | **[Getting Started](Getting-Started)** |
| Understand the design | **[How It Works](How-It-Works)** |
| Learn the web UI | **[Web UI Guide](Web-UI-Guide)** |
| Know what is safe / gated / logged | **[Operations & Hardening](Operations-and-Hardening)** |
| Use the HTTP API | **[API Reference](API-Reference)** |
| Run BloodHound Cypher against OmenHound data | **[Neo4j Schema & Attack Paths](Neo4j-Schema-and-Attack-Paths)** |
| Keep using `bloodhound-ce-python` | **[Coming from BloodHound.py](Coming-from-BloodHound-py)** |
| See what is next | **[Roadmap](Roadmap)** |

---

## What it is (in one table)

| Piece | Command | What it does |
|---|---|---|
| **Collector** | `omenhound collect` | Enumerates AD over LDAP/LDAPS (users, groups, computers, membership) and emits Graph JSON. |
| **Importer** | `omenhound import` | Parses **BloodHound CE / BloodHound.py `--zip`** output into Graph JSON, or pushes it straight into a running server. |
| **Graph backend** | `omenhound serve` | Stores nodes/edges in **Neo4j** using the BloodHound CE schema (in-memory store for demos/tests). |
| **Ingestion API + UI** | `omenhound serve` | HTTP service that ingests graphs and serves a force-directed attack-path UI. |
| **Abuse engine** | *(in the UI/API)* | For every edge, renders a copy-pasteable command from **real node properties**, plus OPSEC and Windows event IDs. |
| **Gated credential ops** | *(off by default)* | Optional `unicodePwd` password change over LDAPS behind token + per-action approval + audit. |

## Screenshots

| Attack-path graph | Dynamic abuse panel | Write-API auth gate |
|---|---|---|
| ![graph](img/webui-graph.png) | ![abuse](img/webui-abuse.png) | ![gate](img/webui-authgate.png) |

## Quickstart (no domain required)

```bash
git clone git@github.com:krazybeastx1/omenhound.git
cd omenhound
make build                                   # -> bin/omenhound

./bin/omenhound collect --collector sample --out graph.json
./bin/omenhound serve   --collector sample --addr 127.0.0.1:8080
# open http://127.0.0.1:8080 — click a node, then an edge
```

The `sample` collector produces a deterministic fake domain, so the entire pipeline
runs with **no AD, no Neo4j, and no credentials**.

## Repository docs

- [`README.md`](https://github.com/krazybeastx1/omenhound#readme) — overview and CLI.
- [`docs/ARCHITECTURE.md`](https://github.com/krazybeastx1/omenhound/blob/main/docs/ARCHITECTURE.md) — components and contracts.
- [`docs/ATTACK-PATHS.md`](https://github.com/krazybeastx1/omenhound/blob/main/docs/ATTACK-PATHS.md) — every edge, with abuse + detection.
- [`docs/THREAT-MODEL.md`](https://github.com/krazybeastx1/omenhound/blob/main/docs/THREAT-MODEL.md) — STRIDE, trust boundaries, residual risk.

## License

MIT (see [`LICENSE`](https://github.com/krazybeastx1/omenhound/blob/main/LICENSE)). Schema
compatibility with [BloodHound CE](https://github.com/SpecterOps/BloodHound) (Apache-2.0).
No BloodHound code is vendored; see [`NOTICE`](https://github.com/krazybeastx1/omenhound/blob/main/NOTICE).
