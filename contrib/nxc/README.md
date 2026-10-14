# nxc module: `omenhound`

A [NetExec](https://github.com/Pennyw0rth/NetExec) module that puts OmenHound's
attack-path guidance in the shell you are already in. For the host you log in to
(and the account you authenticated as) it resolves the graph node, then prints the
**Read** (verify) and **Add** (perform) steps for every edge that leaves it.

The module is **print-only**. It never injects, relays, coerces, or otherwise
executes an abuse command — it only reads OmenHound's reference API and prints.
Commands keep their `{PLACEHOLDER}` tokens in `MODE=playbook`; in `MODE=target`
they are interpolated with the real concrete nodes, exactly as the web Inspector
renders them.

## Install

NetExec loads user modules from `~/.nxc/modules/` (filename must equal the module
name):

```sh
mkdir -p ~/.nxc/modules
cp contrib/nxc/omenhound.py ~/.nxc/modules/omenhound.py

nxc smb --list-modules | grep omenhound
nxc smb --options -M omenhound          # print the option help
```

## Modes

### `target` (default) — what can I do from here?

```sh
nxc smb 10.0.0.25 -u jdoe -p 'Passw0rd!' -M omenhound -o SERVER=http://127.0.0.1:8080
```

The module matches the target you logged in to (`hostname`/`host`) and your
account (`username`) against the OmenHound graph, then prints, for each outgoing
edge, `Read` + `Add` + alternates + OPSEC + event IDs. Incoming edges are listed
as context. If the host cannot be matched (e.g. you connected by IP and the graph
only knows the name), point at a node explicitly:

```sh
... -M omenhound -o SERVER=http://127.0.0.1:8080 -o NODE=WS01
```

### `playbook` — the technique library as a cheatsheet

```sh
nxc smb <any-one-target> -u jdoe -p 'Passw0rd!' -M omenhound \
    -o MODE=playbook -o SERVER=http://127.0.0.1:8080 -o CATEGORY=acl,coercion
```

Prints the grouped 10-category / 54-technique library with placeholders intact.
`CATEGORY` accepts category ids (`acl`, `credentials`, `delegation`, `remote`,
`structure`, `coercion`, `adcs`, `roasting`, `cve`, `setup`) or titles. The
playbook/collect modes print once per nxc run, not once per host.

### `collect` — push a graph into OmenHound

Requires the write token (start the server with `--api-token`).

```sh
# An OmenHound Graph JSON produced by `omenhound collect` / `omenhound export`:
nxc smb <any-one-target> -u jdoe -p 'Passw0rd!' -M omenhound \
    -o MODE=collect -o SERVER=http://127.0.0.1:8080 -o TOKEN=$OMENHOUND_API_TOKEN \
    -o GRAPH=/path/graph.json -o INGEST_MODE=merge

# A BloodHound CE zip/dir (converted and pushed by the `omenhound` binary on PATH):
... -o MODE=collect -o BHCE=/path/bhce_20260101.zip -o TOKEN=$OMENHOUND_API_TOKEN
```

`GRAPH` is POSTed straight to `/api/v1/ingest`; `INGEST_MODE=replace` focuses the
graph on just that file. `BHCE` is handed to `omenhound import --in <path> --api
<server> --token <token>` (merge only), because the BloodHound→Graph conversion
lives in that binary; if it is not on `PATH` the module prints the exact command
to run instead of guessing.

## Options

| Option | Default | Meaning |
|---|---|---|
| `MODE` | `target` | `target` \| `playbook` \| `collect` |
| `SERVER` | `http://127.0.0.1:8080` | OmenHound base URL |
| `TOKEN` | `$OMENHOUND_API_TOKEN` | bearer token, only needed for `collect` |
| `NODE` | *(auto)* | explicit node id/name for `target` mode |
| `CATEGORY` | *(all)* | comma-separated category ids/titles for `playbook` |
| `GRAPH` / `BHCE` | — | input for `collect` mode |
| `INGEST_MODE` | `merge` | `merge` \| `replace`, only for `GRAPH` |
| `DOMAIN` | *(none)* | domain scope for the ingest |
| `INSECURE` | `0` | skip TLS verification |
| `TIMEOUT` | `15` | per-request timeout (seconds) |
| `LIMIT` | `200` | max techniques/edges to print (`0` = unlimited) |

## Endpoints used

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/v1/nodes` | GET | read | resolve the target/account to node ids |
| `/api/v1/nodes/{id}/neighbors` | GET | read | outgoing/incoming edges |
| `/api/v1/abuse?src=&kind=&dst=` | GET | read | interpolated Read + Add for one edge |
| `/api/v1/abuse/playbook` | GET | read | grouped technique library |
| `/api/v1/ingest` | POST | **write** | push a graph (`collect`) |

Read endpoints are unauthenticated; only `collect` needs the token and writes.

## Notes and limits

- The module only runs after a successful nxc login (nxc's contract), so even
  `MODE=playbook`/`collect` need one reachable target with valid credentials.
- `supported_protocols` covers the protocols that expose host/user/domain on the
  connection: `smb, ldap, winrm, rdp, mssql, wmi, ssh, ftp, nfs, vnc`.
- It is registered under the `Enumeration` category, so it is a low-privilege
  module (`on_login`, not `on_admin_login`).

## Tests

`make test-nxc` runs `scripts/nxc_omenhound_test.py`, which serves the OmenHound
API contract from a stub with a self-contained fixture and drives the module with
a fake nxc context/connection. No AD, no nxc and no live server required.
