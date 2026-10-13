"""NetExec (nxc) module: surface OmenHound attack-path guidance from the operator's shell.

OmenHound already exposes read-only reference API endpoints:

  * GET /api/v1/nodes                       — every node in the graph
  * GET /api/v1/nodes/{id}/neighbors        — outgoing/incoming edges for a node
  * GET /api/v1/abuse?src=&kind=&dst=       — the interpolated Read + Add steps for an edge
  * GET /api/v1/abuse/playbook              — the grouped, edge-agnostic technique library
  * POST /api/v1/ingest                     — BloodHound/Graph JSON intake (write token required)

This module is a thin, print-only client over those endpoints. It never injects,
relays, coerces or otherwise executes an abuse command — it prints the Read
(verify) and Add (perform) steps so the operator stays in control.

Modes (-o MODE=...):

  target   (default) resolve the host you logged in to (and the authenticated
           account) to graph nodes and print the Read/Add steps for every edge
           that leaves them.
  playbook print the grouped technique library, optionally filtered with
           -o CATEGORY=acl,coercion. Needs no live target beyond one login.
  collect  push a graph into OmenHound: -o GRAPH=<omenhound graph.json> posts
           directly; -o BHCE=<bloodhound ce zip/dir> is converted and pushed by
           the `omenhound import` binary. Requires -o TOKEN=...

Only use against systems you own or have explicit written authorization to test.
"""

import json
import os
import shutil
import ssl
import subprocess
import traceback
import urllib.error
import urllib.parse
import urllib.request

try:
    from nxc.helpers.misc import CATEGORY
except Exception:  # pragma: no cover - lets the module be imported for offline tests

    class CATEGORY:  # noqa: N801 - mirror the nxc enum's members
        ENUMERATION = "Enumeration"
        CREDENTIAL_DUMPING = "Credential Dumping"
        PRIVILEGE_ESCALATION = "Privilege Escalation"


# Module-level state survives nxc's per-host module re-instantiation: the loader
# caches the module under a fixed name, so this set is shared for the whole run.
# It keeps MODE=playbook / MODE=collect from repeating once per host.
_RAN = set()

_DEFAULT_SERVER = "http://127.0.0.1:8080"
_PAGE = 10000  # OmenHound caps list pages at 10000 items.


def _truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


class NXCModule:
    """Print OmenHound's Read/Add guidance for what you can reach from here."""

    name = "omenhound"
    description = "Query an OmenHound server and print the Read (verify) + Add (perform) steps for the target you authenticated to (MODE=target|playbook|collect)"
    supported_protocols = ["smb", "ldap", "winrm", "rdp", "mssql", "wmi", "ssh", "ftp", "nfs", "vnc"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.server = _DEFAULT_SERVER
        self.token = ""
        self.mode = "target"
        self.node = ""
        # NOTE: the instance attribute that holds the CATEGORY filter option must
        # NOT be named `category` — nxc's ModuleLoader checks module.category on
        # the instantiated module and rejects the module if it isn't one of the
        # CATEGORY enum values. A `self.category` here would shadow the class
        # attribute below ("missing the category variable or invalid category").
        self.cat_filter = ""
        self.graph = ""
        self.bhce = ""
        self.ingest_mode = "merge"
        self.domain_scope = ""
        self.insecure = False
        self.timeout = 15.0
        self.limit = 200
        self._nodes = None

    # -- options ---------------------------------------------------------

    def options(self, context, module_options):
        """MODE      target (default) | playbook | collect
SERVER    OmenHound base URL (default http://127.0.0.1:8080)
TOKEN     bearer token for write endpoints (collect); env OMENHOUND_API_TOKEN
NODE      explicit node id/name to analyse (target mode); default resolves the target host
CATEGORY  comma-separated category ids/titles to filter (playbook mode), e.g. acl,coercion
GRAPH     OmenHound Graph JSON to POST (collect mode)
BHCE      BloodHound CE zip/dir to convert+push via `omenhound import` (collect mode)
INGEST_MODE  merge (default) | replace, only for GRAPH
DOMAIN    domain scope for the ingest (collect mode, optional)
INSECURE  1/true to skip TLS verification
TIMEOUT   per-request timeout in seconds (default 15)
LIMIT     max techniques/edges to print (default 200; 0 = unlimited)"""
        self.context = context
        self.server = (module_options.get("SERVER") or _DEFAULT_SERVER).rstrip("/")
        self.token = module_options.get("TOKEN") or os.environ.get("OMENHOUND_API_TOKEN", "")
        self.mode = (module_options.get("MODE") or "target").strip().lower()
        self.node = (module_options.get("NODE") or "").strip()
        self.cat_filter = (module_options.get("CATEGORY") or "").strip()
        self.graph = (module_options.get("GRAPH") or "").strip()
        self.bhce = (module_options.get("BHCE") or "").strip()
        self.ingest_mode = (module_options.get("INGEST_MODE") or "merge").strip().lower()
        self.domain_scope = (module_options.get("DOMAIN") or "").strip()
        self.insecure = _truthy(module_options.get("INSECURE"))
        self.timeout = float(module_options.get("TIMEOUT") or 15)
        self.limit = int(module_options.get("LIMIT") or 200)
        if self.mode not in ("target", "playbook", "collect"):
            context.log.fail(f"omenhound: unknown MODE={self.mode!r} (want target|playbook|collect)")

    # -- entry point -----------------------------------------------------

    def on_login(self, context, connection):
        self.context = context
        try:
            if self.mode == "playbook":
                self._playbook(connection)
            elif self.mode == "collect":
                self._collect(connection)
            else:
                self._target(connection)
        except _HTTPError as e:
            context.log.fail(f"omenhound: {e.status} from {e.path}: {e.body}")
        except urllib.error.URLError as e:
            context.log.fail(f"omenhound: cannot reach {self.server}: {e.reason}")
        except Exception as e:  # never take down the nxc run
            context.log.fail(f"omenhound: {e}")
            context.log.debug(traceback.format_exc())

    # -- HTTP ------------------------------------------------------------

    def _get(self, path):
        status, obj = self._http("GET", path)
        if status != 200:
            raise _HTTPError(status, path, obj)
        return obj

    def _post(self, path, payload):
        status, obj = self._http("POST", path, payload)
        if status != 200:
            raise _HTTPError(status, path, obj)
        return obj

    def _http(self, method, path, payload=None):
        url = self.server + path
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        ctx = ssl._create_unverified_context() if self.insecure else None
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                body = resp.read()
                return resp.status, (json.loads(body.decode()) if body else None)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace") if e.fp else ""
            try:
                body = json.loads(body).get("error", body)
            except Exception:
                pass
            return e.code, body

    # -- graph helpers ---------------------------------------------------

    def _all_nodes(self):
        if self._nodes is not None:
            return self._nodes
        nodes, offset = [], 0
        while True:
            d = self._get(f"/api/v1/nodes?limit={_PAGE}&offset={offset}")
            page = d.get("nodes") or []
            nodes.extend(page)
            offset += len(page)
            total = d.get("total", offset)
            if not page or offset >= total:
                break
        self._nodes = nodes
        return nodes

    @staticmethod
    def _terms(node):
        for key in ("name", "sam_account_name", "id"):
            v = (node.get(key) or "").strip().upper()
            if v:
                yield v

    def _match(self, terms, kinds=None):
        """Case-insensitive match on name/sAMAccountName/id: equal, id+'$',
        FQDN prefix (host.example.com for host), or the part before '@'."""
        wanted = [t.strip().upper() for t in terms if t and t.strip()]
        if not wanted:
            return []
        out, seen = [], set()
        for n in self._all_nodes():
            if kinds and n.get("kind") not in kinds:
                continue
            if n["id"] in seen:
                continue
            for h in self._terms(n):
                if any(h == w or h == w + "$" or h.startswith(w + ".") or h.split("@")[0] == w for w in wanted):
                    out.append(n)
                    seen.add(n["id"])
                    break
        return out

    def _neighbors(self, node_id):
        return self._get(f"/api/v1/nodes/{urllib.parse.quote(node_id, safe='')}/neighbors")

    def _abuse(self, edge):
        q = urllib.parse.urlencode({"src": edge["source"], "kind": edge["kind"], "dst": edge["target"]})
        status, obj = self._http("GET", "/api/v1/abuse?" + q)
        return obj if status == 200 else None

    # -- rendering -------------------------------------------------------

    def _label(self, nodes, node_id):
        for n in nodes:
            if n["id"] == node_id:
                name = n.get("name") or n.get("sam_account_name") or n["id"]
                return f"{name} [{n.get('kind')}]"
        return node_id

    def _emit_steps(self, block, *, title=None, edge=None, summary=None):
        """Print the Read/Add split for one rendered edge or playbook technique."""
        log = self.context.log
        head = title or edge
        if head:
            log.display(f"  {head}")
        if summary:
            log.display(f"    {summary}")
        read = (block.get("read") or "").strip()
        command = (block.get("command") or "").strip()
        log.highlight(f"    Read : {read or '(no verify step provided)'}")
        log.highlight(f"    Add  : {command}")
        for i, alt in enumerate(block.get("alternates") or []):
            log.display(f"    Alt{'' if i == 0 else str(i)} : {alt}")
        opsec = (block.get("opsec") or "").strip()
        if opsec:
            log.display(f"    OPSEC: {opsec}")
        events = block.get("event_ids") or []
        if events:
            log.display(f"    Events: " + ", ".join(str(e) for e in events))
        requires = (block.get("requires") or "").strip()
        if requires:
            log.display(f"    Needs: {requires}")
        for w in block.get("warnings") or []:
            log.display(f"    warn : {w}")

    def _limit(self, items):
        return items if self.limit <= 0 else items[: self.limit]

    # -- MODE=target -----------------------------------------------------

    def _target(self, connection):
        log = self.context.log
        host = getattr(connection, "hostname", "") or getattr(connection, "host", "")
        domain = getattr(connection, "domain", "") or ""
        user = getattr(connection, "username", "") or ""

        if self.node:
            subjects = self._match(self.node.split(","))
            if not subjects:
                log.fail(f"omenhound: no node matches NODE={self.node!r} on {self.server}")
                return
        else:
            targets = [t for t in (getattr(connection, "hostname", ""), getattr(connection, "host", "")) if t]
            subjects = self._match(targets, kinds={"Computer"})
            user_node = self._match([user]) if user else []
            subjects += [n for n in user_node if n["id"] not in {s["id"] for s in subjects}]

        if not subjects:
            log.fail(
                f"omenhound: no graph node matches host={host!r} user={user!r} "
                f"(domain {domain!r}); run the module with -o NODE=<id|name> to pick one"
            )
            return

        key = ("target", self.server, host, domain, user, tuple(sorted(s["id"] for s in subjects)))
        if key in _RAN:
            return
        _RAN.add(key)

        nodes = self._all_nodes()
        log.highlight(f"OmenHound: {len(subjects)} node(s) resolved from {host or user} on {self.server}")
        printed = 0
        for n in subjects:
            role = "host" if n.get("kind") == "Computer" else "principal"
            log.highlight(f"{role}: {n.get('name')} [{n.get('kind')}] {n['id']}")
            nb = self._neighbors(n["id"])
            outgoing = nb.get("outgoing") or []
            incoming = nb.get("incoming") or []
            if not outgoing and not incoming:
                log.display("  no relationships in the graph")
            for e in self._limit(outgoing):
                r = self._abuse(e)
                header = f"{self._label(nodes, e['source'])} --{e['kind']}--> {self._label(nodes, e['target'])}"
                if r is None:
                    log.display(f"  {header}  (no abuse template for this edge)")
                    continue
                self._emit_steps(r, title=header, summary=r.get("summary"))
                printed += 1
            for e in self._limit(incoming):
                log.display(
                    f"  context: {self._label(nodes, e['source'])} --{e['kind']}--> {self._label(nodes, e['target'])} "
                    f"(reachable by another principal)"
                )
        if printed == 0:
            log.display("OmenHound: no outgoing abuse templates for the resolved node(s).")

    # -- MODE=playbook ---------------------------------------------------

    def _playbook(self, connection):
        key = ("playbook", self.server, self.cat_filter)
        if key in _RAN:
            return
        _RAN.add(key)

        log = self.context.log
        data = self._get("/api/v1/abuse/playbook")
        cats = data.get("categories") or []
        if self.cat_filter:
            want = {c.strip().lower() for c in self.cat_filter.split(",") if c.strip()}
            cats = [c for c in cats if c.get("id", "").lower() in want or c.get("title", "").lower() in want]
        if not cats:
            log.fail(f"omenhound: no categories match CATEGORY={self.cat_filter!r}")
            return

        total = sum(len(c.get("techniques") or []) for c in cats)
        log.highlight(f"OmenHound technique library — {len(cats)} categories / {total} techniques (reference only; never executed)")
        for c in cats:
            log.success(f"{c.get('title') or c.get('id')}  [{c.get('id')}]")
            if c.get("note"):
                log.display(f"  {c['note']}")
            for t in self._limit(c.get("techniques") or []):
                label = t.get("title") or t.get("id")
                if t.get("edge"):
                    label += f"  ({t['edge']})"
                self._emit_steps(t, title=label, summary=t.get("summary"))

    # -- MODE=collect ----------------------------------------------------

    def _collect(self, connection):
        log = self.context.log
        if not self.token:
            log.fail("omenhound: collect writes to the server; set -o TOKEN=<write token> (or $OMENHOUND_API_TOKEN)")
            return
        key = ("collect", self.server, self.graph, self.bhce, self.ingest_mode, self.domain_scope)
        if key in _RAN:
            return
        if not self.graph and not self.bhce:
            log.display(
                "omenhound: nothing to collect. Use -o GRAPH=<omenhound graph.json> "
                "(produced by `omenhound collect`/`omenhound export`) or "
                "-o BHCE=<bloodhound ce zip|dir> (converted by `omenhound import`)."
            )
            return
        _RAN.add(key)

        if self.graph:
            if not os.path.isfile(self.graph):
                log.fail(f"omenhound: GRAPH not found: {self.graph}")
                return
            with open(self.graph, "rb") as fh:
                payload = json.load(fh)
            if not isinstance(payload, dict) or "nodes" not in payload:
                log.fail(f"omenhound: {self.graph} is not an OmenHound Graph JSON (expected a 'nodes' key)")
                return
            q = {"mode": self.ingest_mode}
            if self.domain_scope:
                q["domain"] = self.domain_scope
            res = self._post("/api/v1/ingest?" + urllib.parse.urlencode(q), payload)
            batch = f" batch={res['batch']['id']}" if isinstance(res.get("batch"), dict) else ""
            log.success(f"omenhound: ingested {res.get('nodes')} nodes / {res.get('edges')} edges into {self.server}{batch}")
            return

        binary = shutil.which("omenhound")
        if not binary:
            log.fail(
                "omenhound: the `omenhound` binary is not on PATH, so a BloodHound CE export cannot be converted here. "
                f"Run it manually: omenhound import --in {self.bhce} --api {self.server} --token <token>"
            )
            return
        cmd = [binary, "import", "--in", self.bhce, "--api", self.server, "--token", self.token]
        log.display("omenhound: running " + " ".join(cmd[:-1] + ["<token>"]))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout * 20)
        for line in (proc.stdout or "").splitlines():
            log.display("  " + line)
        if proc.returncode == 0:
            log.success(f"omenhound: pushed {self.bhce} into {self.server}")
        else:
            for line in (proc.stderr or "").splitlines():
                log.fail("  " + line)
            log.fail(f"omenhound: import exited {proc.returncode}")


class _HTTPError(Exception):
    def __init__(self, status, path, body):
        super().__init__(f"{status} {path}: {body}")
        self.status = status
        self.path = path
        self.body = body
