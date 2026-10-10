# Getting Started

## Requirements

| Use case | You need |
|---|---|
| Building / sample mode / import | **Go 1.26+**, nothing else |
| Collecting from AD | Network access to a DC on **636/tcp (LDAPS)** and a bind account |
| Neo4j backend | A reachable **Neo4j 5.x** (`bolt://host:7687`) |

Everything is dependency-free at runtime: the web UI is embedded in the binary, there
is no build step for the frontend, and no CDN is used.

## Build

```bash
git clone git@github.com:krazybeastx1/omenhound.git
cd omenhound
make build          # -> bin/omenhound
./bin/omenhound version
```

`make vet test build` is exactly what CI runs.

---

## 1. Try it offline (no domain)

The `sample` collector ships a deterministic fake domain so you can exercise the whole
pipeline — collect, ingest, attack-path UI, abuse rendering — with zero infrastructure.

```bash
# collect a graph and look at it
./bin/omenhound collect --collector sample --out graph.json

# serve the API + web UI using the in-memory store
./bin/omenhound serve --collector sample --addr 127.0.0.1:8080
```

Open <http://127.0.0.1:8080>, click a node, then click an edge. Or `make run-sample`.

At this point you have already proven: collection, the graph store, the ingestion API,
the web UI, and the dynamic abuse renderer.

---

## 2. Collect from a real domain (LDAP/LDAPS)

OmenHound this pass supports **LDAP simple bind over LDAPS**. Plaintext LDAP is refused
unless you explicitly opt in with `--allow-plaintext-ldap` (lab only).

```bash
export OMENHOUND_PASSWORD='...'            # keep secrets out of argv/history

./bin/omenhound collect \
  --collector ldap \
  --domain corp.local --server dc01.corp.local \
  --ldaps --username 'CORP\svc_omenhound' \
  --password-stdin --out corp.json
```

### BloodHound.py-compatible flags

If you already use `bloodhound-ce-python`, the collector accepts the same short flags:

| flag | meaning |
|---|---|
| `-d`, `--domain` | AD domain (e.g. `corp.local`) |
| `-u`, `--username` | bind username |
| `-p`, `--password` | bind password (prefer `--password-stdin` / `$OMENHOUND_PASSWORD`) |
| `-ns`, `--nameserver` | DNS server used for **DC SRV discovery** (`_ldap._tcp.dc._msdcs.<domain>`) |
| `-dc`, `--domain-controller` | DC host, if you don't want SRV discovery |
| `--use-ldaps`, `--ldaps` | use LDAPS (636) |
| `-c`, `--collectionmethod` | comma-separated methods, or `all` / `default` / `dc` |
| `-op`, `--outputprefix` | filename prefix for `--zip` output |
| `--zip` | write a **BloodHound CE v5 archive** instead of Graph JSON |
| `--ldap-channel-binding` | accepted for parity; a no-op for LDAP simple bind over TLS |

Example with SRV discovery and a CE-compatible archive:

```bash
./bin/omenhound collect --collector ldap -d corp.local -ns 10.0.0.10 \
  -u 'CORP\svc' --password-stdin --use-ldaps -c group,objectprops \
  --zip -op corp_ --out corp_collection.zip
```

### Collection methods (honest partial support)

OmenHound implements the **`group`**, **`objectprops`**, **`acl`**, **`trusts`** and
**`container`** methods: users, groups, computers and membership; their properties;
object security descriptors → ACL edges; `trustedDomain` objects → `TrustedBy` edges;
and OUs/GPOs/containers → `Contains` + `GPLink` edges. `-c dc` / `-c dconly` expands to
`group,trusts,objectprops,acl,container`, so it skips nothing. Any *other* method you
request is reported explicitly — never silently dropped:

```
collect: WARNING: collection method "session" is not implemented — skipped
collect: WARNING: collection method "localadmin" is not implemented — skipped
```

If you ask for **only** unimplemented methods (e.g. `-c session`), the collector
**refuses to run** rather than pretending it collected something.

Each pass is self-sufficient: `-c acl` emits ACL edges and creates the
`OU`/`GPO`/`Container` nodes it needs, and `-c container` builds the containment tree
without needing `acl`. One caveat on validation — the parsers and mappings are tested
against **impacket**-generated descriptors and hand-built fixtures, but the live LDAP
path has not yet been exercised against a real domain controller, so treat first
contact with a DC as unverified.

See **[Coming from BloodHound.py](Coming-from-BloodHound-py)** for the full method table.

---

## 3. Import BloodHound.py / BloodHound CE output

OmenHound imports the JSON or `--zip` output of `bloodhound-ce-python` directly.

```bash
# your existing workflow
bloodhound-ce-python -d cascade.local -u s.smith -p '...' -ns 10.129.46.41 -c all --zip
# -> 20260101120000_cascade.local_bloodhound.zip

# import it
./bin/omenhound import --in 20260101120000_cascade.local_bloodhound.zip --out cascade.json
```

Or push it straight into a running server (needs `--api-token` on `serve`):

```bash
./bin/omenhound import --in collection.zip --api http://127.0.0.1:8080 --token "$OMENHOUND_API_TOKEN"
```

The importer keeps **SIDs/GUIDs verbatim**, follows the BloodHound CE edge directions,
and reports anything it dropped rather than inventing results:

```
import: 1284 nodes, 3610 edges, 12 placeholders from 7 file(s) (domain "CASCADE.LOCAL")
import: ACE right names with no OmenHound edge (skipped): map[...]
```

---

## 4. Serve with the production graph backend (Neo4j)

```bash
export OMENHOUND_NEO4J_PASSWORD='...'
export OMENHOUND_API_TOKEN="$(openssl rand -hex 32)"

./bin/omenhound serve \
  --neo4j-uri bolt://127.0.0.1:7687 --neo4j-user neo4j \
  --collector none --addr 127.0.0.1:8080
```

Then push a collection into it:

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/ingest \
  -H "Authorization: Bearer $OMENHOUND_API_TOKEN" \
  --data-binary @corp.json
```

Because the graph uses the BloodHound CE schema, you can now point BloodHound CE (or
your own Cypher) at the same database.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ldap: refusing plaintext LDAP` | Add `--ldaps`. Plaintext bind leaks credentials; only override with `--allow-plaintext-ldap` on a lab. |
| `collector: unknown collection method "x"` | Typo, or a method OmenHound doesn't know. Known names are listed in the error. |
| `ldap: none of the requested collection methods are implemented` | You asked for only unimplemented methods. Use `group`/`objectprops`/`acl`/`trusts`/`container`/`all`/`dc`. |
| `dns: could not discover a DC` | SRV lookup failed; pass `-dc <host>` instead of `-ns`, or check DNS. |
| `import: no JSON files inside …zip` | Wrong archive. Point at the `--zip` output from BloodHound.py/CE. |
| `write API is disabled` | Start `serve` with `--api-token`. |
| `unauthorized` on a write | Missing/incorrect `Authorization: Bearer <token>`. |

Next: **[How It Works](How-It-Works)** →
