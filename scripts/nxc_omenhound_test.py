#!/usr/bin/env python3
"""Offline tests for contrib/nxc/omenhound.py (the NetExec module).

The module is a print-only HTTP client over OmenHound's read endpoints plus the
ingest write endpoint, so it can be tested without AD, without nxc and without a
live OmenHound server: this script starts a stub HTTP server that speaks the same
contract (nodes / neighbors / abuse / playbook / ingest) and drives the module
against it with a fake nxc context and connection.

The stub serves a self-contained fixture, so a FAIL here means the module broke,
not that the environment lacked data. It never fabricates a pass.

Usage:
    python3 scripts/nxc_omenhound_test.py
Exit code is non-zero if any check fails.
"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, os.pardir, "contrib", "nxc", "omenhound.py")

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(("pass" if cond else "fail", name, detail))
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(detail)) if detail and not cond else ""))


# ---- fixture ------------------------------------------------------------

D = "S-1-5-21-1004336348-1177238915-682003330"
NODES = [
    {"id": D, "kind": "Domain", "name": "OMENHOUND", "domain": "omenhound.lab"},
    {"id": f"{D}-1000", "kind": "Computer", "name": "DC01", "sam_account_name": "DC01$", "domain": "omenhound.lab",
     "distinguished_name": "CN=DC01,OU=Domain Controllers,DC=omenhound,DC=lab"},
    {"id": f"{D}-1003", "kind": "Computer", "name": "WS01", "sam_account_name": "WS01$", "domain": "omenhound.lab",
     "distinguished_name": "CN=WS01,OU=Workstations,DC=omenhound,DC=lab"},
    {"id": f"{D}-1103", "kind": "User", "name": "John Doe", "sam_account_name": "jdoe", "domain": "omenhound.lab",
     "distinguished_name": "CN=John Doe,OU=Users,DC=omenhound,DC=lab"},
    {"id": f"{D}-513", "kind": "Group", "name": "Domain Users", "sam_account_name": "Domain Users", "domain": "omenhound.lab"},
]
EDGES = [
    {"source": f"{D}-1103", "target": f"{D}-1003", "kind": "GenericAll", "props": {}},
    {"source": f"{D}-1103", "target": f"{D}-513", "kind": "MemberOf", "props": {}},
    {"source": f"{D}-513", "target": f"{D}-1000", "kind": "AdminTo", "props": {}},
]
PLAYBOOK = {
    "categories": [
        {"id": "acl", "title": "Access control (ACL)", "note": "rights you can hand yourself",
         "techniques": [
             {"id": "GenericAll", "title": "Full control over the object", "edge": "GenericAll",
              "summary": "Full control.", "read": "READ-GenericAll", "command": "ADD-GenericAll",
              "alternates": ["ALT-GenericAll"], "opsec": "events on the DC", "event_ids": [4724]},
             {"id": "WriteDacl", "title": "Grant yourself rights", "edge": "WriteDacl",
              "read": "READ-WriteDacl", "command": "ADD-WriteDacl", "tags": ["acl"]},
         ]},
        {"id": "coercion", "title": "Coercion & relay", "techniques": [
            {"id": "Coerce", "title": "Force an authentication", "read": "READ-Coerce",
             "command": "ADD-Coerce", "requires": "a listener"},
        ]},
    ]
}


def abuse_for(edge):
    src, dst = edge["source"], edge["target"]
    return {
        "edge": edge,
        "source": next(n for n in NODES if n["id"] == src),
        "target": next(n for n in NODES if n["id"] == dst),
        "summary": f"abuse {edge['kind']}",
        "read": f"READ:{edge['kind']}:{src}->{dst}",
        "command": f"ADD:{edge['kind']}:{src}->{dst}",
        "alternates": [f"ALT:{edge['kind']}"],
        "opsec": "noisy",
        "event_ids": [4728],
    }


RECORD = {"ingest": [], "paths": []}


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        RECORD["paths"].append(u.path)
        if u.path == "/api/v1/nodes":
            q = urllib.parse.parse_qs(u.query)
            offset = int((q.get("offset") or ["0"])[0])
            limit = int((q.get("limit") or ["10000"])[0])
            page = [n for n in NODES]
            self._json({"total": len(NODES), "limit": limit, "offset": offset,
                        "nodes": page[offset:offset + limit]})
        elif u.path.endswith("/neighbors"):
            nid = u.path.split("/nodes/")[1].rsplit("/neighbors", 1)[0]
            self._json({"outgoing": [e for e in EDGES if e["source"] == nid],
                        "incoming": [e for e in EDGES if e["target"] == nid]})
        elif u.path == "/api/v1/abuse":
            q = urllib.parse.parse_qs(u.query)
            edge = {"source": (q.get("src") or [""])[0], "target": (q.get("dst") or [""])[0],
                    "kind": (q.get("kind") or [""])[0]}
            known = any(e["source"] == edge["source"] and e["target"] == edge["target"] and e["kind"] == edge["kind"]
                        for e in EDGES)
            if known:
                self._json(abuse_for(edge))
            else:
                self._json({"error": "no abuse template"}, 404)
        elif u.path == "/api/v1/abuse/playbook":
            self._json(PLAYBOOK)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        RECORD["ingest"].append({"path": self.path, "auth": self.headers.get("Authorization"),
                                 "body": json.loads(body) if body else None})
        self._json({"nodes": len((json.loads(body) if body else {}).get("nodes", [])),
                    "edges": len((json.loads(body) if body else {}).get("edges", [])),
                    "batch": {"id": "batch-1"}})


# ---- fake nxc objects ---------------------------------------------------

class Log:
    def __init__(self):
        self.lines = []
        self.text = ""

    def _rec(self, level, msg):
        self.lines.append((level, str(msg)))
        self.text = "\n".join(m for _, m in self.lines)

    def display(self, m): self._rec("display", m)
    def success(self, m): self._rec("success", m)
    def fail(self, m): self._rec("fail", m)
    def highlight(self, m): self._rec("highlight", m)
    def info(self, m): self._rec("info", m)
    def debug(self, m): self._rec("debug", m)
    def error(self, m): self._rec("error", m)


class Ctx:
    def __init__(self):
        self.log = Log()


class Conn:
    def __init__(self, hostname, host=None, domain="omenhound.lab", username="jdoe"):
        self.hostname = hostname
        self.host = host or hostname
        self.domain = domain
        self.username = username
        self.admin_privs = False


def load_module():
    spec = importlib.util.spec_from_file_location("omenhound_nxc_test", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(mod, options, conn):
    ctx = Ctx()
    inst = mod.NXCModule()
    inst.options(ctx, options)
    inst.on_login(ctx, conn)
    return ctx.log


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    mod = load_module()

    # --- playbook mode ---
    mod._RAN.clear()
    log = run(mod, {"SERVER": base, "MODE": "playbook"}, Conn("WS01"))
    check("playbook lists categories", "Access control (ACL)" in log.text and "Coercion" in log.text, log.text)
    check("playbook shows Read and Add steps", "Read : READ-GenericAll" in log.text and "Add  : ADD-GenericAll" in log.text, log.text)
    check("playbook marks reference-only", "reference only; never executed" in log.text, log.text)
    check("playbook counts techniques", "2 categories / 3 techniques" in log.text, log.text)

    log2 = run(mod, {"SERVER": base, "MODE": "playbook"}, Conn("WS01"))
    check("playbook prints once per run", log2.lines == [], log2.text)

    mod._RAN.clear()
    log = run(mod, {"SERVER": base, "MODE": "playbook", "CATEGORY": "coercion"}, Conn("WS01"))
    check("playbook CATEGORY filter", "ADD-Coerce" in log.text and "GenericAll" not in log.text, log.text)

    # --- target mode ---
    mod._RAN.clear()
    log = run(mod, {"SERVER": base, "MODE": "target"}, Conn("WS01"))
    check("target resolves the authed principal", "John Doe [User]" in log.text, log.text)
    check("target resolves the host", "WS01 [Computer]" in log.text, log.text)
    check("target prints Read then Add for the edge",
          "READ:GenericAll" in log.text and "ADD:GenericAll" in log.text, log.text)
    read_line = next((m for lv, m in log.lines if lv == "highlight" and m.strip().startswith("Read :")), "")
    add_line = next((m for lv, m in log.lines if lv == "highlight" and m.strip().startswith("Add  :")), "")
    check("Read and Add are distinct", read_line and add_line and read_line != add_line, (read_line, add_line))
    check("target shows OPSEC/events", "OPSEC:" in log.text and "Events:" in log.text, log.text)

    mod._RAN.clear()
    log = run(mod, {"SERVER": base, "MODE": "target", "NODE": "DC01"}, Conn("WS01"))
    check("target NODE override resolves DC01", "DC01" in log.text, log.text)

    mod._RAN.clear()
    log = run(mod, {"SERVER": base, "MODE": "target"}, Conn("NOPE01", username="nobody"))
    check("target with no match fails honestly", "no graph node matches" in log.text, log.text)

    # --- collect mode ---
    mod._RAN.clear()
    graph = {"nodes": NODES, "edges": EDGES, "meta": {"collector": "test"}}
    fd, path = tempfile.mkstemp(prefix="omenhound_graph_", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(graph, fh)
    RECORD["ingest"].clear()
    log = run(mod, {"SERVER": base, "MODE": "collect", "TOKEN": "tok", "GRAPH": path, "INGEST_MODE": "replace"}, Conn("WS01"))
    check("collect posts the graph", len(RECORD["ingest"]) == 1, RECORD["ingest"])
    check("collect sends the bearer token",
          RECORD["ingest"] and RECORD["ingest"][0]["auth"] == "Bearer tok", RECORD["ingest"])
    check("collect passes mode=replace", RECORD["ingest"] and "mode=replace" in RECORD["ingest"][0]["path"], RECORD["ingest"])
    check("collect reports ingestion", "ingested 5 nodes / 3 edges" in log.text, log.text)

    mod._RAN.clear()
    log = run(mod, {"SERVER": base, "MODE": "collect", "GRAPH": path}, Conn("WS01"))
    check("collect requires a token", "TOKEN" in log.text and "ingested" not in log.text, log.text)
    os.unlink(path)

    # --- error handling ---
    mod._RAN.clear()
    log = run(mod, {"SERVER": "http://127.0.0.1:1", "MODE": "playbook"}, Conn("WS01"))
    check("unreachable server fails, does not crash", any(lv == "fail" for lv, _ in log.lines), log.text)

    server.shutdown()

    fails = sum(1 for s, _, _ in RESULTS if s == "fail")
    print(f"\n{len(RESULTS) - fails} passed, {fails} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
