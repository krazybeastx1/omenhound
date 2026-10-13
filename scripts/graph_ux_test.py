#!/usr/bin/env python3
"""Browser tests for the OmenHound Graph Explorer UX upgrade.

Drives the real UI in a real browser and asserts observable behaviour for the
features added on top of the existing graph engine:

  * starting-node workflow (search picker, chip, separation from selection)
  * session-aware analysis (HasSession edges, sessions-only filter, empty state)
  * safe credential metadata (masked by default, references only)
  * path analysis integration (direction/filters, highlight on the graph)
  * Inspector correctness for nodes of each kind and for relationship edges

The app is dependency-free (no bundler), so these tests run against a live
server. Provide a scratch server the test may ingest a self-contained fixture
into; that keeps the checks deterministic without touching a real dataset.

Usage:
    python3 scripts/graph_ux_test.py [--base URL] [--token TOKEN] [--ingest]

Defaults:
    --base   http://127.0.0.1:8080
    --token  $OMENHOUND_API_TOKEN

Without --ingest the script only runs read-only checks and SKIPs (with a
reason) any check whose evidence is absent from the dataset — it never
fabricates a pass.
"""
import argparse
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(("pass" if cond else "fail", name, detail))
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(detail)) if detail and not cond else ""))


def skip(name, reason):
    RESULTS.append(("skip", name, reason))
    print("SKIP " + name + " :: " + reason)


def js(d, script, *args):
    return d.execute_script(script, *args)


def driver():
    opts = Options()
    opts.binary_location = "/usr/bin/chromium"
    for a in ("--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
              "--disable-gpu", "--window-size=1600,1000"):
        opts.add_argument(a)
    svc = Service("/usr/bin/chromedriver")
    return webdriver.Chrome(service=svc, options=opts)


# Self-contained fixture: sessions (User->Computer), memberships, a 2-hop path
# User->Group->GPO, and credential *references* under the documented namespace.
USER = "S-1-5-21-9-1001"
USER2 = "S-1-5-21-9-1002"
HOST = "S-1-5-21-9-2001"
GROUP = "S-1-5-21-9-3001"
GPO = "S-1-5-21-9-4001"
DOMAIN = "S-1-5-21-9"
# Analytics fixture — properties/edges the canned attack-path queries key on.
KERB = "S-1-5-21-9-5001"
ASREP = "S-1-5-21-9-5002"
DELEG = "S-1-5-21-9-5003"
DCSYNC = "S-1-5-21-9-5004"
OWNED = "S-1-5-21-9-5005"
HVTARGET = "S-1-5-21-9-5006"
LAPSREADER = "S-1-5-21-9-5007"
# Diamond fixture: two equal-length routes from DIAMOND_START to DIAMOND_TARGET.
DIA_S = "S-1-5-21-9-6001"
DIA_A = "S-1-5-21-9-6002"
DIA_B = "S-1-5-21-9-6003"
DIA_T = "S-1-5-21-9-6004"

FIXTURE = {
    "nodes": [
        {"id": DOMAIN, "kind": "Domain", "name": "UXLAB", "domain": "uxlab.test"},
        {"id": USER, "kind": "User", "name": "UXUSER", "domain": "uxlab.test", "sam_account_name": "uxuser",
         "distinguished_name": "CN=uxuser,CN=Users,DC=uxlab,DC=test",
         "props": {"enabled": "true", "admincount": "true",
                   "cred.type": "nthash", "cred.status": "imported",
                   "cred.source": "import", "cred.ref": "3008f5b6a1c9e2d4f7b3a6c8e1d9f2a5b7c4e6d8",
                   "cred.observed_at": "2026-01-02T03:04:05Z"}},
        {"id": USER2, "kind": "User", "name": "SVC", "domain": "uxlab.test", "sam_account_name": "svc",
         "props": {"enabled": "true"}},
        {"id": HOST, "kind": "Computer", "name": "UXHOST01", "domain": "uxlab.test", "sam_account_name": "uxhost01$",
         "props": {"os": "Windows Server 2022"}},
        {"id": GROUP, "kind": "Group", "name": "UX ADMINS", "domain": "uxlab.test"},
        {"id": GPO, "kind": "GPO", "name": "UX GPO", "domain": "uxlab.test"},
        {"id": KERB, "kind": "User", "name": "KERBSVC", "domain": "uxlab.test",
         "props": {"enabled": "true", "hasspn": "true",
                   "serviceprincipalname": "MSSQLSvc/db.uxlab.test:1433"}},
        {"id": ASREP, "kind": "User", "name": "ASREPUSER", "domain": "uxlab.test",
         "props": {"enabled": "true", "dontreqpreauth": "true"}},
        {"id": DELEG, "kind": "Computer", "name": "DELEGHOST", "domain": "uxlab.test",
         "props": {"unconstraineddelegation": "true"}},
        {"id": DCSYNC, "kind": "User", "name": "REPLADMIN", "domain": "uxlab.test",
         "props": {"enabled": "true"}},
        {"id": OWNED, "kind": "User", "name": "OWNEDUSER", "domain": "uxlab.test", "props": {"owned": "true"}},
        {"id": HVTARGET, "kind": "Group", "name": "HIGH VALUE", "domain": "uxlab.test",
         "props": {"highvalue": "true"}},
        {"id": LAPSREADER, "kind": "User", "name": "LAPSREADER", "domain": "uxlab.test",
         "props": {"enabled": "true"}},
        {"id": DIA_S, "kind": "User", "name": "DIAMONDSTART", "domain": "uxlab.test"},
        {"id": DIA_A, "kind": "Group", "name": "DIAMONDA", "domain": "uxlab.test"},
        {"id": DIA_B, "kind": "Group", "name": "DIAMONDB", "domain": "uxlab.test"},
        {"id": DIA_T, "kind": "Domain", "name": "DIAMONDTARGET", "domain": "uxlab.test"},
    ],
    "edges": [
        {"source": USER, "target": GROUP, "kind": "MemberOf"},
        {"source": GROUP, "target": GPO, "kind": "GenericAll"},
        {"source": USER, "target": HOST, "kind": "HasSession"},
        {"source": USER2, "target": HOST, "kind": "HasSession"},
        {"source": DCSYNC, "target": DOMAIN, "kind": "GetChangesAll"},
        {"source": LAPSREADER, "target": HOST, "kind": "ReadLAPSPassword"},
        {"source": DIA_S, "target": DIA_A, "kind": "MemberOf"},
        {"source": DIA_S, "target": DIA_B, "kind": "GenericWrite"},
        {"source": DIA_A, "target": DIA_T, "kind": "GenericWrite"},
        {"source": DIA_B, "target": DIA_T, "kind": "GenericAll"},
    ],
    "meta": {"collector": "ux-fixture", "domain": "uxlab.test"},
}

# A deliberately different, smaller graph used to prove that replace-mode
# ingestion drops whatever was previously in the store.
MINI = {
    "nodes": [{"id": "UX-MINI-1", "kind": "User", "name": "MINIONLY", "domain": "uxlab.test"}],
    "edges": [],
    "meta": {"collector": "ux-mini", "domain": "uxlab.test"},
}

# Second-domain fixture used to prove domain-scoped ingestion, alternative path
# discovery and scoped deletion. It carries a 2-hop and a 3-hop route so a
# "shortest only" search and a "shortest + alternatives" search differ.
ALT_S = "S-1-5-21-9-7001"
ALT_M = "S-1-5-21-9-7002"
ALT_T = "S-1-5-21-9-7003"
ALT_X = "S-1-5-21-9-7004"
ALT_Y = "S-1-5-21-9-7005"
ALT_Z = "S-1-5-21-9-7006"

ALT = {
    "nodes": [
        {"id": ALT_S, "kind": "User", "name": "ALTSRC", "domain": "alt.test"},
        {"id": ALT_M, "kind": "Group", "name": "ALTMID", "domain": "alt.test"},
        {"id": ALT_T, "kind": "Domain", "name": "ALTTGT", "domain": "alt.test"},
        {"id": ALT_X, "kind": "Group", "name": "ALTX", "domain": "alt.test"},
        {"id": ALT_Y, "kind": "OU", "name": "ALTY", "domain": "alt.test"},
    ],
    "edges": [
        {"source": ALT_S, "target": ALT_M, "kind": "MemberOf"},
        {"source": ALT_M, "target": ALT_T, "kind": "GenericWrite"},
        {"source": ALT_S, "target": ALT_X, "kind": "MemberOf"},
        {"source": ALT_X, "target": ALT_Y, "kind": "GenericWrite"},
        {"source": ALT_Y, "target": ALT_T, "kind": "GenericWrite"},
    ],
    "meta": {"collector": "ux-alt", "domain": "alt.test"},
}

# A single extra node in alt.test; ingesting it after a deletion preview makes
# that preview's fingerprint stale, which the server must detect.
ALT_EXTRA = {
    "nodes": [{"id": ALT_Z, "kind": "Computer", "name": "ALTZ", "domain": "alt.test"}],
    "edges": [],
    "meta": {"collector": "ux-alt", "domain": "alt.test"},
}


def http_get(base, path, token=None):
    req = urllib.request.Request(base.rstrip("/") + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, json.loads(r.read().decode())


def http_get_code(base, path, token=None):
    """Like http_get but returns the status for error responses too."""
    try:
        return http_get(base, path, token)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def http_post(base, path, body, token=None, raw=None):
    data = raw if raw is not None else json.dumps(body).encode()
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def http_delete(base, path, token=None):
    req = urllib.request.Request(base.rstrip("/") + path, method="DELETE")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--token", default=os.environ.get("OMENHOUND_API_TOKEN", ""))
    ap.add_argument("--ingest", action="store_true",
                    help="ingest the self-contained fixture into --base before testing (use a scratch server)")
    args = ap.parse_args()
    base = args.base

    # ---- fixture / dataset preparation --------------------------------
    if args.ingest:
        if not args.token:
            print("--ingest needs --token (or OMENHOUND_API_TOKEN)"); return 2
        st, _ = http_post(base, "/api/v1/ingest", FIXTURE, token=args.token)
        if st != 200:
            print("fixture ingest failed: HTTP %s" % st); return 2
    st, stats = http_get(base, "/api/v1/stats")
    check("api: /stats exposes nodes/edges/kinds (contract compatible)",
          st == 200 and "nodes" in stats and "edges" in stats and "kinds" in stats, stats)
    gst, graph = http_get(base, "/api/v1/graph")
    check("api: /graph returns {nodes,edges} (contract compatible)",
          gst == 200 and "nodes" in graph and "edges" in graph, {"keys": list(graph.keys())})

    d = driver()
    d.get(base + "/#/graph")
    WebDriverWait(d, 30).until(lambda x: js(x, "return typeof nodes!=='undefined' && nodes.length>0"))
    WebDriverWait(d, 30).until(lambda x: js(x, "return temp<=LAYOUT.minTemp"))
    js(d, "window.__errs=[];window.addEventListener('error',e=>window.__errs.push(String(e.message)));")

    present = js(d, """return {nodes:nodes.map(n=>n.id), edges:edges.map(e=>({s:e.source,t:e.target,k:e.kind}))}""")
    ids = set(present["nodes"])
    kinds = set(present["edges"] and [e["k"] for e in present["edges"]] or [])
    has_fixture = USER in ids and HOST in ids
    has_sessions = "HasSession" in kinds
    has_analytics = KERB in ids and DCSYNC in ids and LAPSREADER in ids

    # ---- analytics (canned attack-path queries) -------------------
    st, qlist = http_get(base, "/api/v1/analytics")
    qids = set(q.get("id") for q in (qlist.get("queries") or []))
    check("api: /analytics lists the canned queries",
          st == 200 and {"kerberoastable", "dcsync", "high-value-targets"} <= qids,
          {"status": st, "count": len(qids)})
    if has_analytics:
        st, kerb = http_get(base, "/api/v1/analytics/kerberoastable")
        found = set(f["node"]["id"] for f in (kerb.get("findings") or []))
        check("api: kerberoastable finds the SPN user (and nothing else)",
              st == 200 and kerb.get("count") == 1 and found == {KERB},
              {"status": st, "count": kerb.get("count"), "found": sorted(found)})
        st, dc = http_get(base, "/api/v1/analytics/dcsync")
        rel = set(r for f in (dc.get("findings") or []) for r in (f.get("related") or []))
        check("api: dcsync lists replication rights over the domain",
              st == 200 and dc.get("count") == 1 and DOMAIN in rel, dc)
        st, laps = http_get(base, "/api/v1/analytics/laps-readable")
        check("api: edge-backed query lists the reader and the target host",
              st == 200 and laps.get("count") == 1 and
              (laps.get("findings") or [{}])[0]["node"]["id"] == LAPSREADER and
              HOST in ((laps.get("findings") or [{}])[0].get("related") or []), laps)
        st, adm = http_get(base, "/api/v1/analytics/adminto")
        notes = " ".join(adm.get("notes") or [])
        check("api: empty analytics result carries an honest absence note",
              st == 200 and adm.get("count") == 0 and "AdminTo" in notes, adm)
    else:
        skip("api: kerberoastable finds the SPN user (and nothing else)", "analytics fixture not present (use --ingest)")
        skip("api: dcsync lists replication rights over the domain", "analytics fixture not present (use --ingest)")
        skip("api: edge-backed query lists the reader and the target host", "analytics fixture not present (use --ingest)")
        skip("api: empty analytics result carries an honest absence note", "analytics fixture not present (use --ingest)")
    code, _ = http_get_code(base, "/api/v1/analytics/not-a-query")
    check("api: unknown analytics query is a 404", code == 404, {"status": code})

    # ---- abuse technique library ----------------------------------
    st, playbook = http_get(base, "/api/v1/abuse/playbook")
    cats = playbook.get("categories") or []
    techs = [t for c in cats for t in (c.get("techniques") or [])]
    edge_techs = [t for t in techs if t.get("edge")]
    check("api: /abuse/playbook returns a grouped technique library",
          st == 200 and len(cats) >= 8 and len(techs) >= 40,
          {"status": st, "categories": len(cats), "techniques": len(techs)})
    sst, supported = http_get(base, "/api/v1/abuse/supported")
    sup = set(supported.get("edges") or [])
    played = set(t.get("edge") for t in edge_techs)
    check("api: the playbook covers every edge /abuse/supported advertises",
          sst == 200 and len(sup) >= 20 and sup <= played,
          {"supported": len(sup), "in_playbook": len(played)})
    check("api: playbook edge commands stay templated (no fabricated output)",
          edge_techs and all("{" in (t.get("command") or "") for t in edge_techs),
          {"edge_techniques": len(edge_techs)})
    check("api: every technique carries a distinct read (verify) step",
          bool(techs) and all((t.get("read") or "").strip() for t in techs) and
          all((t.get("read") or "") != (t.get("command") or "") for t in techs),
          {"techniques": len(techs)})
    check("api: playbook edge read steps stay templated (no fabricated output)",
          edge_techs and all("{" in (t.get("read") or "") for t in edge_techs),
          {"edge_techniques": len(edge_techs)})

    try:
        # ---- 1/2. baseline load + selection (regression) --------------
        check("graph loads without regressions", len(present["nodes"]) > 0 and len(present["edges"]) > 0,
              {"nodes": len(present["nodes"]), "edges": len(present["edges"])})
        base_sel = js(d, """const n=nodes[0]; const p=toScreen(n); const r=canvas.getBoundingClientRect();
            const fire=(t,b)=>canvas.dispatchEvent(new PointerEvent(t,{clientX:r.left+p.x,clientY:r.top+p.y,bubbles:true,pointerId:1,pointerType:'mouse',button:0,buttons:b}));
            fire('pointerdown',1);fire('pointerup',0);
            return {sel: !!selectedNode, panel: !document.getElementById('panel-node').hidden};""")
        check("node selection still works", base_sel["sel"] and base_sel["panel"], base_sel)
        # ---- 2b. edge selection (any edge, dataset-generic) ----------
        edge_sel = js(d, """const r=canvas.getBoundingClientRect();
            const fire=(t,b,x,y)=>canvas.dispatchEvent(new PointerEvent(t,{clientX:r.left+x,clientY:r.top+y,bubbles:true,pointerId:1,pointerType:'mouse',button:0,buttons:b}));
            let done=null;
            for (const e of edges) {
              const a=byId.get(e.source), b=byId.get(e.target);
              if (!a||!b) continue;
              for (const f of [0.5,0.35,0.65,0.2,0.8]) {
                const sp=toScreen({x:a.x+(b.x-a.x)*f, y:a.y+(b.y-a.y)*f});
                fire('pointerdown',1,sp.x,sp.y); fire('pointerup',0,sp.x,sp.y);
                if (selectedEdge===e) { done={kind:e.kind, src:e.source, tgt:e.target,
                    summary:document.getElementById('edge-summary').textContent,
                    srcName:nodeLabel(a), tgtName:nodeLabel(b)}; break; }
              }
              if (done) break;
            }
            return done || {kind:null, summary:''};""")
        check("edge selection shows the correct source and target",
              edge_sel["kind"] is not None and edge_sel["srcName"] in edge_sel["summary"] and edge_sel["tgtName"] in edge_sel["summary"],
              edge_sel)

        # ---- the selected edge shows read (verify) + add commands -----
        try:
            ab = WebDriverWait(d, 10).until(lambda x: js(x, """const r=document.getElementById('edge-read');
                const c=document.getElementById('edge-command');
                if(!r||!c||c.textContent==='loading…') return false;
                return {read:r.textContent, command:c.textContent, wrap:!document.getElementById('edge-read-wrap').hidden};"""))
            if "No abuse template" in ab["command"]:
                skip("edge panel shows a distinct read (verify) step", "selected edge has no abuse template")
            else:
                check("edge panel shows a distinct read (verify) step",
                      ab["wrap"] and ab["read"] and ab["read"] != ab["command"] and "{" not in ab["read"],
                      {"read": ab["read"][:70]})
        except Exception as e:  # noqa: BLE001
            check("edge panel shows a distinct read (verify) step", False, str(e))

        # ---- panels: collapse / hide / reopen ------------------------
        pan = js(d, """const p=document.getElementById('panel');
            document.getElementById('panelCollapse').click(); const c1=p.classList.contains('collapsed');
            document.getElementById('panelCollapse').click(); const c2=p.classList.contains('collapsed');
            document.getElementById('toggleInspector').click(); const h1=p.classList.contains('hidden');
            document.getElementById('toggleInspector').click(); const h2=p.classList.contains('hidden');
            return {c1:c1, c2:c2, h1:h1, h2:h2};""")
        check("Inspector collapses and hides/reopens without errors",
              pan["c1"] and not pan["c2"] and pan["h1"] and not pan["h2"], pan)

        # ---- keyboard: Escape clears selection, / focuses search ------
        kb = js(d, """selectNode(nodes[0]);
            document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
            const cleared = selectedNode===null;
            document.dispatchEvent(new KeyboardEvent('keydown',{key:'/',bubbles:true}));
            const focused = document.activeElement && document.activeElement.id==='graphSearch';
            if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
            return {cleared:cleared, focused:focused};""")
        check("keyboard: Escape clears the selection and / focuses search",
              kb["cleared"] and kb["focused"], kb)

        # ---- technique library in the Inspector empty state ----------
        WebDriverWait(d, 10).until(lambda x: js(x, "return document.querySelectorAll('#libraryBody .lib-category').length>0"))
        lib = js(d, """return {
            cats: document.querySelectorAll('#libraryBody .lib-category').length,
            techs: document.querySelectorAll('#libraryBody .lib-tech').length,
            copy: document.querySelectorAll('#libraryBody .lib-copy').length,
            cmd: document.querySelectorAll('#libraryBody .lib-cmd').length,
            read: document.querySelectorAll('#libraryBody .lib-read').length,
            standalone: document.querySelectorAll('#libraryBody .lib-tech-edge.standalone').length,
            visible: !document.getElementById('panel-empty').hidden
        };""")
        check("technique library renders in the empty Inspector",
              lib["visible"] and lib["cats"] >= 8 and lib["techs"] >= 40 and
              lib["copy"] == lib["techs"] and lib["cmd"] == lib["techs"] and
              lib["read"] == lib["techs"] and lib["standalone"] >= 1,
              lib)
        lf = js(d, """const inp=document.getElementById('librarySearch');
            inp.value='petitpotam'; inp.dispatchEvent(new Event('input',{bubbles:true}));
            const n=document.querySelectorAll('#libraryBody .lib-tech').length;
            inp.value=''; inp.dispatchEvent(new Event('input',{bubbles:true}));
            return {filtered:n, restored:document.querySelectorAll('#libraryBody .lib-tech').length};""")
        check("technique library filters and restores",
              0 < lf["filtered"] < lib["techs"] and lf["restored"] == lib["techs"], lf)

        # ---- start / target are independent of the selection ----------
        stt = js(d, """const a=nodes[0].id, b=nodes[1].id;
            selectNode(byId.get(a)); setStartNode(a);
            const chip1 = !document.getElementById('startNodeChip').hidden;
            selectNode(byId.get(b)); setTargetNode(b);
            return {start:startNodeId, target:targetNodeId, sel:selectedNode&&selectedNode.id,
                    chip1:chip1, chip2:!document.getElementById('targetNodeChip').hidden, a:a, b:b};""")
        check("starting node and target are independent concepts (and of the selection)",
              stt["start"] == stt["a"] and stt["target"] == stt["b"] and stt["sel"] == stt["b"] and stt["chip1"] and stt["chip2"],
              stt)

        # ---- 3. starting-node workflow --------------------------------
        if has_fixture:
            start = js(d, """selectNode(byId.get('%s'));
                const inp=document.getElementById('startNodeSearch'); inp.value='UXUSER';
                inp.dispatchEvent(new Event('input',{bubbles:true}));
                return {sel: selectedNode&&selectedNode.id};""" % USER)
            got = False
            for _ in range(40):
                if js(d, "return document.querySelectorAll('#startNodeRes .suggest-item[data-id]').length") > 0:
                    got = True; break
                time.sleep(0.25)
            picked = ""
            if got:
                picked = js(d, """const el=document.querySelector('#startNodeRes .suggest-item[data-id]'); el.click();
                    return {start:startNodeId, chip:!document.getElementById('startNodeChip').hidden,
                            chipText:document.getElementById('startNodeChip').textContent,
                            focusEnabled:!document.getElementById('setStartFromNode').disabled};""")
            check("start-from picker sets the starting node",
                  got and picked and picked["start"] == USER and picked["chip"] is True, {"got": got, "picked": picked})
            check("starting node is shown as a distinct chip",
                  bool(picked) and "UXUSER" in (picked or {}).get("chipText", ""), picked)

            # ---- 4. changing the start node does not corrupt the graph --
            before = js(d, "return {n:nodes.length, e:edges.length, sel:selectedNode&&selectedNode.id}")
            after = js(d, """setStartNode('%s');
                return {n:nodes.length, e:edges.length, sel:selectedNode&&selectedNode.id, start:startNodeId};""" % HOST)
            check("changing the starting node does not corrupt the graph",
                  after["n"] == before["n"] and after["e"] == before["e"] and after["start"] == HOST, after)
            check("starting node stays separate from the selected node",
                  js(d, """selectNode(byId.get('%s')); return {start:startNodeId, sel:selectedNode.id, distinct:startNodeId!==selectedNode.id};""" % GPO)
                  .get("distinct") is True)

            # ---- 5. Inspector per entity kind ---------------------------
            insp = js(d, """const out={};
                for (const [k,id] of [['User','%s'],['Computer','%s'],['Group','%s'],['GPO','%s']]) {
                  selectNode(byId.get(id));
                  out[k]={rows:document.querySelectorAll('#node-props dt').length,
                          title:document.getElementById('node-title').textContent,
                          conn:document.getElementById('nodeConnected').textContent,
                          outLi:document.querySelectorAll('#node-out li').length,
                          inLi:document.querySelectorAll('#node-in li').length};
                }
                selectNode(byId.get('%s'));
                return out;""" % (USER, HOST, GROUP, GPO, USER))
            check("Inspector shows structured detail for every entity kind",
                  all(insp[k]["rows"] >= 3 and insp[k]["conn"].isdigit() for k in insp), insp)

        # ---- 5b. sessions section (dataset-generic) ------------------
        if has_sessions:
            sess_pairs = js(d, "return edges.filter(e=>e.kind==='HasSession').map(e=>[e.source,e.target])")
            endpoints = set([x for p in sess_pairs for x in p])
            s0, t0 = sess_pairs[0]
            su = js(d, """selectNode(byId.get('%s'));
                return {html:document.getElementById('node-sessions').textContent,
                        hasNote: document.querySelector('#node-sessions .session-note')!==null,
                        other: nodeLabel(byId.get('%s'))};""" % (s0, t0))
            sv = js(d, """selectNode(byId.get('%s'));
                return {html:document.getElementById('node-sessions').textContent,
                        other: nodeLabel(byId.get('%s'))};""" % (t0, s0))
            check("Inspector lists observed sessions for an identity",
                  ("Observed on hosts" in su["html"] or "Identities observed here" in su["html"]) and su["other"] in su["html"],
                  {"html": su["html"], "other": su["other"]})
            check("Inspector lists the counterparty from the other side",
                  su["other"] in su["html"] or sv["other"] in sv["html"], {"u": su["html"], "v": sv["html"]})

            # session edge evidence note
            note = js(d, """const e=edges.find(x=>x.kind==='HasSession');
                const a=toScreen(byId.get(e.source)), b=toScreen(byId.get(e.target)); const r=canvas.getBoundingClientRect();
                const x=(a.x+b.x)/2, y=(a.y+b.y)/2;
                const fire=(t,b)=>canvas.dispatchEvent(new PointerEvent(t,{clientX:r.left+x,clientY:r.top+y,bubbles:true,pointerId:1,pointerType:'mouse',button:0,buttons:b}));
                fire('pointerdown',1);fire('pointerup',0);
                return {hidden: document.getElementById('edge-session-note').hidden,
                        text: document.getElementById('edge-session-note').textContent};""")
            check("session edge shows an evidence note (no invented timestamps)",
                  note["hidden"] is False and "Observed session" in note["text"], note)

            # ---- 7. sessions-only filter --------------------------------
            filt = js(d, """document.getElementById('sessionsOnly').click();
                const v=visibleNodes().map(n=>n.id);
                const vis=edges.filter(e=>!edgeHidden(e)).map(e=>e.kind);
                document.getElementById('sessionsOnly').click();
                return {visible:v, kinds:[...new Set(vis)], pressed:document.getElementById('sessionsOnly').getAttribute('aria-pressed')};""")
            check("sessions-only filter keeps session nodes and drops the rest",
                  set(filt["kinds"]) == {"HasSession"} and set(filt["visible"]) == endpoints, filt)
            check("toggling the sessions filter restores the graph",
                  js(d, "return visibleNodes().length") == len(present["nodes"]))
        else:
            skip("Inspector lists observed sessions for an identity", "no HasSession evidence in dataset")
            skip("session edge shows an evidence note (no invented timestamps)", "no HasSession evidence in dataset")
            skip("sessions-only filter keeps session nodes and drops the rest", "no HasSession evidence in dataset")

        # ---- 8. honest session empty state ---------------------------
        if has_fixture:
            empty = js(d, """selectNode(byId.get('%s'));
                return document.getElementById('node-sessions').textContent;""" % GPO)
            check("missing session data produces an honest empty state",
                  "No session evidence" in empty, empty)

        # ---- 9/10. credential metadata --------------------------------
        if has_fixture:
            cred = js(d, """selectNode(byId.get('%s'));
                const t=document.getElementById('node-credentials').textContent;
                const span=document.querySelector('#node-credentials .secret');
                return {text:t, masked: span? span.textContent : null,
                        rawInDom: t.indexOf('3008f5b6a1c9e2d4f7b3a6c8e1d9f2a5b7c4e6d8')!==-1,
                        reveal: document.querySelector('#node-credentials .reveal-secret')!==null};""" % USER)
            check("credential metadata is masked by default",
                  cred["masked"] and "•" in cred["masked"] and cred["rawInDom"] is False, cred)
            check("credential section offers an explicit reveal",
                  cred["reveal"] is True, cred)
            leak = js(d, """let leaks=[];
                try { for (let i=0;i<localStorage.length;i++){ const v=localStorage.getItem(localStorage.key(i)); if((v||'').indexOf('3008f5b6a1c9e2d4')!==-1) leaks.push('localStorage'); } } catch(_){}
                if (location.href.indexOf('3008f5b6a1c9e2d4')!==-1) leaks.push('url');
                return leaks;""")
            check("secrets never reach the URL or browser storage", leak == [], leak)
            miss = js(d, """selectNode(byId.get('%s'));
                return document.getElementById('node-credentials').textContent;""" % USER2)
            check("missing credential metadata does not break the Inspector",
                  "No credential evidence" in miss and js(d, "return !document.getElementById('panel-node').hidden") is True, miss)

        # ---- 10b. toolbar layout (hidden controls + no overlap) -------
        layout = js(d, """
            const cs=(id)=>getComputedStyle(document.getElementById(id));
            const hiddenOk=(id)=>{const e=document.getElementById(id); return !e.hasAttribute('hidden') || cs(id).display==='none';};
            const box=(id)=>document.getElementById(id).getBoundingClientRect();
            const a=box('findPathsRun'), b=box('findPathsFromGraph');
            const overlapAB=Math.min(a.right,b.right)-Math.max(a.left,b.left);
            return {
              clearOk: hiddenOk('clearPathHighlight'),
              routesOk: hiddenOk('togglePathDrawer'),
              startOk: hiddenOk('startNodeChip'),
              targetOk: hiddenOk('targetNodeChip'),
              findW: Math.round(a.width), fromW: Math.round(b.width),
              overlap: overlapAB,
              labelFits: document.getElementById('findPathsRun').scrollWidth <= Math.ceil(a.width)+1
            };""")
        check("toolbar controls carrying the hidden attribute are not rendered",
              layout["clearOk"] and layout["routesOk"] and layout["startOk"] and layout["targetOk"], layout)
        check("Find Paths and Paths controls fit their labels and do not overlap",
              layout["overlap"] <= 0 and layout["labelFits"] and layout["findW"] > 40 and layout["fromW"] > 40, layout)

        # ---- 11. path analysis direction + filters --------------------
        if has_fixture:
            st, out = http_post(base, "/api/v1/paths/shortest",
                                {"source_id": USER, "target_id": GPO, "direction": "outgoing", "max_depth": 5},
                                token=args.token)
            st2, inc = http_post(base, "/api/v1/paths/shortest",
                                 {"source_id": USER, "target_id": GPO, "direction": "incoming", "max_depth": 5},
                                 token=args.token)
            st3, filt = http_post(base, "/api/v1/paths/shortest",
                                  {"source_id": USER, "target_id": GPO, "direction": "outgoing", "max_depth": 5,
                                   "include_relationship_types": ["MemberOf"]},
                                  token=args.token)
            out_paths = out.get("paths") or []
            inc_paths = inc.get("paths") or []
            filt_paths = filt.get("paths") or []
            check("path search respects direction",
                  len(out_paths) == 1 and out_paths[0]["length"] == 2 and len(inc_paths) == 0,
                  {"out": len(out_paths), "in": len(inc_paths)})
            check("path search respects relationship-type filters",
                  len(filt_paths) == 0, {"paths": len(filt_paths)})
            if out_paths:
                hl = js(d, """highlightPath(%s);
                    return {active:!!pathHighlight, clearBtn:!document.getElementById('clearPathHighlight').hidden,
                            pathNodes:pathHighlight.nodes.size, pathEdges:pathHighlight.edges.size};"""
                         % json.dumps(out_paths[0]))
                check("a found path highlights on the graph and can be cleared",
                      hl["active"] and hl["clearBtn"] and hl["pathEdges"] == 2 and
                      js(d, "clearPathHighlight(); return pathHighlight===null") is True, hl)

                # The canvas itself must receive the path styling. Assert on the
                # real draw() strokes rather than only the pathHighlight state, so
                # a regression in the renderer (not the state) is caught.
                js(d, "highlightPath(%s);" % json.dumps(out_paths[0]))
                rend = js(d, """const orig=ctx.stroke.bind(ctx); const rec=[];
                    ctx.stroke=function(){ rec.push({c:String(ctx.strokeStyle), w:ctx.lineWidth, a:ctx.globalAlpha}); orig(); };
                    draw(); ctx.stroke=orig;
                    const keys=[...pathHighlight.edges];
                    return {edges:keys.length,
                            onPath:keys.map(k=>{const e=edges.find(x=>edgeKey(x)===k); return e?pathEdgeInfo(e):null;}),
                            strokes:rec};""")
                wide = [s for s in rend["strokes"] if s["w"] >= 4 and s["a"] >= 0.9]
                subdued = [s for s in rend["strokes"] if abs(s["a"] - 0.05) < 0.001]
                check("every edge on the selected route is rendered with the path highlight",
                      rend["edges"] == 2 and all(o is not None for o in rend["onPath"]) and len(wide) >= 2,
                      {"onPath": rend["onPath"], "wide": len(wide)})
                check("unrelated edges are subdued (not removed) while a path is focused",
                      len(subdued) >= 1, {"subdued": len(subdued)})
                js(d, "clearPathHighlight();")

                # Clicking a node and opening the Inspector must not clear the route.
                js(d, "highlightPath(%s);" % json.dumps(out_paths[0]))
                persist = js(d, """const before=pathHighlight.edges.size;
                    const first=[...pathHighlight.nodes][0];
                    focusNode(byId.get(first));
                    selectNode(byId.get(first));
                    return {before:before, after:pathHighlight?pathHighlight.edges.size:null,
                            selected:selectedNode?selectedNode.id:null, first:first};""")
                check("clicking a node or opening the Inspector keeps the path highlight",
                      persist["after"] == persist["before"] and persist["selected"] == persist["first"],
                      persist)
                js(d, "clearPathHighlight();")

            # ---- 11b. Path Explorer UI integration --------------------
            js(d, "location.hash='#/paths';")
            WebDriverWait(d, 10).until(lambda x: "view-paths" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))
            for input_id, query, res_id in (("pathSrc", "UXUSER", "pathSrcRes"), ("pathDst", "UX GPO", "pathDstRes")):
                js(d, """const i=document.getElementById('%s'); i.value='%s'; i.dispatchEvent(new Event('input',{bubbles:true}));""" % (input_id, query))
                WebDriverWait(d, 10).until(lambda x, rid=res_id: js(x, "return document.querySelectorAll('#%s .suggest-item[data-id]').length" % rid) > 0)
                js(d, """document.querySelector('#%s .suggest-item[data-id]').click();""" % res_id)
            js(d, "document.getElementById('pathSearch').click();")
            WebDriverWait(d, 15).until(lambda x: js(x, "return document.querySelectorAll('#pathResults .path-item').length>0"))
            js(d, "document.querySelector('#pathResults .show-path-btn').click();")
            WebDriverWait(d, 10).until(lambda x: "view-graph" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))
            ui_path = js(d, """return {view:(document.querySelector('.view.active')||{}).id, active:!!pathHighlight,
                clear:!document.getElementById('clearPathHighlight').hidden};""")
            check("Path Explorer finds a path in the UI and shows it on the graph",
                  ui_path["view"] == "view-graph" and ui_path["active"] and ui_path["clear"], ui_path)
            js(d, "clearPathHighlight(); location.hash='#/graph';")
            WebDriverWait(d, 10).until(lambda x: "view-graph" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))

        # ---- 11d. multi-path discovery + Path Explorer drawer --------
        if has_fixture:
            st, dia = http_post(base, "/api/v1/paths/shortest",
                                {"source_id": DIA_S, "target_id": DIA_T, "direction": "outgoing",
                                 "max_depth": 5, "max_paths": 10}, token=args.token)
            dia_paths = dia.get("paths") or []
            check("multi-path search returns equal-length alternatives",
                  st == 200 and len(dia_paths) == 2 and all(len(p["relationships"]) == 2 for p in dia_paths),
                  {"status": st, "paths": len(dia_paths)})

            js(d, "location.hash='#/graph';")
            WebDriverWait(d, 10).until(lambda x: "view-graph" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))
            js(d, "setStartNode('%s', {focus:false}); setTargetNode('%s');" % (DIA_S, DIA_T))
            WebDriverWait(d, 10).until(lambda x: js(x, "return !document.getElementById('findPathsRun').disabled"))
            js(d, "document.getElementById('findPathsRun').click();")
            WebDriverWait(d, 20).until(lambda x: js(x, "return pathState && pathState.status==='ready' && pathState.paths.length===2"))
            drawer = js(d, """return {visible:!document.getElementById('pathDrawer').hidden,
                items:document.querySelectorAll('#pathDrawerResults .path-item').length,
                toggle:!document.getElementById('togglePathDrawer').hidden,
                sel:pathState.selected,
                nodes:pathHighlight.nodes.size, edges:pathHighlight.edges.size,
                start:pathRoleOf('%s'), target:pathRoleOf('%s'),
                mid:pathRoleOf('%s')};""" % (DIA_S, DIA_T, DIA_A))
            check("Find Paths populates the Path Explorer drawer and highlights every route",
                  drawer["visible"] and drawer["items"] == 2 and drawer["toggle"] and drawer["sel"] == -1
                  and drawer["edges"] == 4 and drawer["nodes"] == 4, drawer)
            check("start, target and intermediate nodes carry distinct roles",
                  drawer["start"] == "start" and drawer["target"] == "target" and drawer["mid"] == "intermediate", drawer)

            sub = js(d, """return {unrelatedOnPath:inPathNodes('%s'), unrelatedLoaded:byId.has('%s'),
                pathNodeOnPath:inPathNodes('%s')};""" % (HVTARGET, HVTARGET, DIA_A))
            check("unrelated nodes are subdued, not removed from the graph",
                  sub["unrelatedOnPath"] is False and sub["unrelatedLoaded"] is True and sub["pathNodeOnPath"] is True, sub)

            focused = js(d, """document.querySelectorAll('#pathDrawerResults .path-item')[1].click();
                return {sel:pathState.selected, routes:pathHighlight.paths.length,
                        hasOthers:pathHighlight.paths.some((p,i)=>i!==pathState.selected)};""")
            check("selecting a route in the drawer focuses it", focused["sel"] == 1 and focused["hasOthers"] is True, focused)

            cyc = js(d, """document.getElementById('pathNext').click(); const a=pathState.selected;
                document.getElementById('pathPrev').click(); const b=pathState.selected; return {a:a,b:b};""")
            check("Next / Previous cycle between routes", cyc["a"] == 0 and cyc["b"] == 1, cyc)

            allp = js(d, """document.getElementById('pathShowAll').click();
                return {sel:pathState.selected, edges:pathHighlight.edges.size};""")
            check("Show all restores the whole-route highlight", allp["sel"] == -1 and allp["edges"] == 4, allp)

            exp = js(d, "focusPath(0, {}); return exportPathJSON(0);")
            try:
                ej = json.loads(exp)
            except Exception:
                ej = None
            check("a route exports as JSON with its nodes and steps",
                  ej is not None and ej["path"]["length"] == 2 and len(ej["path"]["nodes"]) == 3 and
                  len(ej["path"]["steps"]) == 2, {"exported": exp[:60] if exp else None})

            fitres = js(d, "document.getElementById('pathFit').click(); return {sel:pathState.selected, k:view.k>0};")
            check("Fit to path keeps the selection without error", fitres["sel"] == 0 and fitres["k"] is True, fitres)

            # Inspect from the drawer: an intermediate node chip selects the real
            # node, a relationship chip opens the real edge inspector.
            js(d, "focusPath(0, {});")
            insp = js(d, """const chip=document.querySelector('#pathDrawerResults .path-node[data-node]');
                if(!chip) return {chip:false};
                const id=chip.dataset.node; chip.click();
                return {chip:true, id:id, sel:selectedNode?selectedNode.id:null,
                        view:(document.querySelector('.view.active')||{}).id};""")
            check("clicking an intermediate node in the Path Explorer inspects it",
                  insp["chip"] and insp["sel"] == insp["id"] and insp["view"] == "view-graph", insp)

            js(d, "focusPath(0, {});")
            insr = js(d, """const chip=document.querySelector('#pathDrawerResults .path-rel[data-rel]');
                if(!chip) return {chip:false};
                chip.click();
                return {chip:true, edge:selectedEdge?selectedEdge.kind:null};""")
            check("clicking a relationship chip in the Path Explorer inspects the edge",
                  insr["chip"] and insr["edge"] is not None, insr)

            # A superseded search must not overwrite the newer one's result.
            js(d, """runPathSearch('%s','%s'); runPathSearch('%s','%s');""" % (DIA_S, DIA_T, USER, GROUP))
            WebDriverWait(d, 20).until(lambda x: js(x, "return pathState.status!=='loading'"))
            time.sleep(0.5)
            stale = js(d, "return {src:pathState.sourceId, dst:pathState.targetId}")
            check("a superseded path search cannot overwrite the newer one",
                  stale["src"] == USER and stale["dst"] == GROUP, stale)

            # Reverse swaps the endpoints; a one-way pair yields an honest empty state.
            js(d, "setStartNode('%s', {focus:false}); setTargetNode('%s'); runPathSearch('%s','%s');" % (USER, GROUP, USER, GROUP))
            WebDriverWait(d, 20).until(lambda x: js(x, "return pathState.status==='ready'"))
            js(d, "document.getElementById('pathReverse').click();")
            WebDriverWait(d, 20).until(lambda x: js(x, "return pathState.sourceId==='%s' && pathState.status!=='loading'" % GROUP))
            rev = js(d, """return {src:pathState.sourceId, dst:pathState.targetId, status:pathState.status,
                text:document.getElementById('pathDrawerResults').textContent};""")
            check("Reverse swaps the endpoints; a one-way pair reports an honest empty state",
                  rev["src"] == GROUP and rev["dst"] == USER and rev["status"] == "empty" and "No paths found" in rev["text"], rev)

            clr = js(d, """document.getElementById('pathDrawerClear').click();
                return {hidden:document.getElementById('pathDrawer').hidden, path:pathHighlight,
                        items:document.querySelectorAll('#pathDrawerResults .path-item').length};""")
            check("Clear restores the graph and empties the Path Explorer",
                  clr["hidden"] is True and clr["path"] is None and clr["items"] == 0, clr)
            js(d, "location.hash='#/graph';")

        # ---- 11c. Attack Paths view (canned analytics) ---------------
        d.execute_script("arguments[0].click();", d.find_element(By.CSS_SELECTOR, '.nav-btn[data-view="attacks"]'))
        WebDriverWait(d, 15).until(lambda x: "view-attacks" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))
        WebDriverWait(d, 15).until(lambda x: js(x, "return document.querySelectorAll('#attackQueries .attack-card[data-query]').length>0"))
        cards = js(d, "return [...document.querySelectorAll('#attackQueries .attack-card[data-query]')].map(e=>e.dataset.query)")
        check("Attack Paths view lists the canned queries",
              "kerberoastable" in cards and "dcsync" in cards, {"cards": len(cards)})
        filt_cards = js(d, """const i=document.getElementById('attackSearch'); i.value='kerberoast';
            i.dispatchEvent(new Event('input',{bubbles:true}));
            return [...document.querySelectorAll('#attackQueries .attack-card[data-query]')].map(e=>e.dataset.query);""")
        check("Attack Paths query filter narrows the list",
              filt_cards == ["kerberoastable"], {"filtered": filt_cards})
        js(d, """const i=document.getElementById('attackSearch'); i.value=''; i.dispatchEvent(new Event('input',{bubbles:true}));""")
        if has_analytics:
            js(d, """document.querySelector('#attackQueries .attack-card[data-query="kerberoastable"]').click();""")
            WebDriverWait(d, 15).until(lambda x: js(x, "return document.querySelectorAll('#attackResult .attack-finding').length>0"))
            res = js(d, """return {count:document.querySelectorAll('#attackResult .attack-finding').length,
                text:document.getElementById('attackResult').textContent,
                highlight:document.getElementById('attackHighlight')!==null};""")
            check("running a canned query shows its findings in the UI",
                  res["count"] == 1 and "KERBSVC" in res["text"] and res["highlight"], res)
            js(d, "document.getElementById('attackHighlight').click();")
            WebDriverWait(d, 10).until(lambda x: "view-graph" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))
            hl = js(d, "return {view:(document.querySelector('.view.active')||{}).id, match:matchIds.has('%s')}" % KERB)
            check("a finding can be highlighted on the Graph Explorer",
                  hl["view"] == "view-graph" and hl["match"] is True, hl)
            js(d, "matchIds=new Set(); applyFilters();")
        else:
            skip("running a canned query shows its findings in the UI", "analytics fixture not present (use --ingest)")
            skip("a finding can be highlighted on the Graph Explorer", "analytics fixture not present (use --ingest)")

        # ---- 12. invalid / incomplete data is handled safely -----------
        if args.token:
            st, resp = http_post(base, "/api/v1/ingest", None, token=args.token, raw=b"{not json")
            after_bad = js(d, "return {n:nodes.length}")
            check("invalid ingest payload is rejected without corrupting state",
                  st == 400 and len(present["nodes"]) == after_bad["n"], {"status": st, "resp": resp})
        else:
            skip("invalid ingest payload is rejected without corrupting state", "no --token supplied")

        # ---- 13. navigation + ingestion views still work ---------------
        d.execute_script("arguments[0].click();", d.find_element(By.CSS_SELECTOR, '.nav-btn[data-view="ingestion"]'))
        WebDriverWait(d, 10).until(lambda x: "view-ingestion" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))
        d.execute_script("arguments[0].click();", d.find_element(By.CSS_SELECTOR, '.nav-btn[data-view="graph"]'))
        WebDriverWait(d, 10).until(lambda x: "view-graph" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))
        check("navigation and ingestion views still work",
              js(d, "return nodes.length") == len(present["nodes"]))

        # ---- 13b. domain-scoped ingestion + ingestion management ----------
        if args.token and has_fixture:
            # A scoped ingest attributes the file to the selected domain and is
            # recorded as one batch, keeping it separate from the other domain.
            st, ar = http_post(base, "/api/v1/ingest?domain=alt.test", ALT, token=args.token)
            check("ingest scoped to a domain records a batch for that domain",
                  st == 200 and (ar.get("batch") or {}).get("domain") == "alt.test"
                  and (ar.get("batch") or {}).get("id"), {"status": st, "batch": ar.get("batch")})

            # A file whose objects belong to another domain is refused, never
            # silently reassigned to the selected domain.
            st_bad, bad = http_post(base, "/api/v1/ingest?domain=alt.test", MINI, token=args.token)
            check("scoped ingest refuses objects that belong to another domain",
                  st_bad == 400 and "domain" in json.dumps(bad).lower(), {"status": st_bad, "body": bad})

            # The dry-run preview reports what would be written and writes nothing.
            st, pv = http_post(base, "/api/v1/ingest/preview?domain=alt.test", ALT, token=args.token)
            p = pv.get("preview") or {}
            check("ingest preview reports counts without writing",
                  st == 200 and p.get("nodes") == len(ALT["nodes"])
                  and p.get("assigned_nodes") == len(ALT["nodes"]) and p.get("mismatch_nodes") == 0, pv)

            # Domain + batch history reflect the scoped import.
            st, doms = http_get(base, "/api/v1/ingest/domains")
            names = {x.get("domain") for x in (doms.get("domains") or [])}
            check("management domain list includes both domains",
                  st == 200 and "alt.test" in names and "uxlab.test" in names, {"domains": sorted(names)})
            st, batches = http_get(base, "/api/v1/ingest/batches")
            check("management batch history lists the scoped batch",
                  st == 200 and any(b.get("domain") == "alt.test" for b in (batches.get("batches") or [])),
                  {"count": len(batches.get("batches") or [])})

            # Alternative route discovery: shortest-only returns the 2-hop route,
            # while alternative mode also returns the longer, simple 3-hop route.
            st_s, short = http_post(base, "/api/v1/paths/shortest",
                                    {"source_id": ALT_S, "target_id": ALT_T, "direction": "outgoing",
                                     "max_depth": 5, "max_paths": 10}, token=args.token)
            st_a, alts = http_post(base, "/api/v1/paths/shortest",
                                   {"source_id": ALT_S, "target_id": ALT_T, "direction": "outgoing",
                                    "max_depth": 5, "max_paths": 10, "alternative": True}, token=args.token)
            sp = short.get("paths") or []
            ap = alts.get("paths") or []
            check("shortest-only search returns just the minimum-hop route",
                  st_s == 200 and len(sp) == 1 and len(sp[0]["relationships"]) == 2, short)
            check("alternative mode also returns the longer simple route",
                  st_a == 200 and sorted(len(p2["relationships"]) for p2 in ap) == [2, 3], alts)

            # A domain filter excludes routes whose nodes belong to another domain.
            st, domp = http_post(base, "/api/v1/paths/shortest",
                                 {"source_id": ALT_S, "target_id": ALT_T, "direction": "outgoing",
                                  "max_depth": 5, "max_paths": 10, "include_domains": ["uxlab.test"]},
                                 token=args.token)
            check("domain filter excludes routes outside the selected domain",
                  st == 200 and len(domp.get("paths") or []) == 0, domp)

            # UI: the management tab lists batches and domains, renders a deletion
            # preview and requires the domain name to be typed to confirm.
            js(d, "document.getElementById('ingestToken').value=arguments[0];", args.token)
            d.execute_script("arguments[0].click();", d.find_element(By.CSS_SELECTOR, '.nav-btn[data-view="ingestion"]'))
            WebDriverWait(d, 10).until(lambda x: "view-ingestion" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))
            js(d, "document.querySelector('.ingestion-tabs .tab-btn[data-tab=\"mgmt\"]').click();")
            WebDriverWait(d, 15).until(lambda x: js(x, "return document.querySelectorAll('#batchRows .batch-del').length>0"))
            mgmt = js(d, """return {tab:!document.getElementById('tab-mgmt').hidden,
                batches:document.querySelectorAll('#batchRows .batch-del').length,
                domains:[...document.querySelectorAll('#domainRows .domain-del')].map(b=>b.dataset.domain)};""")
            check("ingestion management tab lists batches and domains",
                  mgmt["tab"] and mgmt["batches"] >= 1 and "alt.test" in mgmt["domains"], mgmt)

            js(d, "document.querySelector('#batchRows .batch-del').click();")
            WebDriverWait(d, 15).until(lambda x: js(x, "return !document.getElementById('delConfirmArea').hidden"))
            prv = js(d, """return {preview:/Deletion preview/.test(document.getElementById('delPreview').textContent),
                nameShown:!document.getElementById('delNameWrap').hidden,
                counts:document.querySelectorAll('#delPreview .count-cell').length};""")
            check("batch deletion preview renders counts and no name prompt",
                  prv["preview"] and prv["counts"] >= 4 and prv["nameShown"] is False, prv)
            js(d, "document.getElementById('delCancel').click();")
            check("cancelling a deletion preview clears it without deleting",
                  js(d, "return document.getElementById('delPreview').hidden && document.getElementById('delConfirmArea').hidden"))

            # Selected-record deletion preview through the UI (scoped to a domain).
            js(d, """document.getElementById('recScope').value='domain';
                document.getElementById('recTarget').value='alt.test';
                document.getElementById('recNodes').value='%s';""" % ALT_S)
            js(d, "document.getElementById('recPreviewBtn').click();")
            WebDriverWait(d, 15).until(lambda x: js(x, "return !document.getElementById('delConfirmArea').hidden"))
            recp = js(d, """return {preview:/Deletion preview/.test(document.getElementById('delPreview').textContent),
                nameShown:!document.getElementById('delNameWrap').hidden};""")
            check("selected-record deletion preview renders inside a domain scope",
                  recp["preview"] and recp["nameShown"] is False, recp)
            js(d, "document.getElementById('delCancel').click();")

            js(d, "document.querySelector('#domainRows .domain-del[data-domain=\"alt.test\"]').click();")
            WebDriverWait(d, 15).until(lambda x: js(x, "return !document.getElementById('delConfirmArea').hidden"))
            dpr = js(d, """return {nameShown:!document.getElementById('delNameWrap').hidden,
                disabled:document.getElementById('delConfirm').disabled,
                text:document.getElementById('delPreview').textContent};""")
            check("domain deletion preview requires typing the domain name",
                  dpr["nameShown"] and dpr["disabled"] is True and "alt.test" in dpr["text"], dpr)
            js(d, "document.getElementById('delCancel').click();")
            # Return to the upload tab so the file-picker tests can interact.
            js(d, "document.querySelector('.ingestion-tabs .tab-btn[data-tab=\"web\"]').click();")

            # Scoped deletion: preview, reject a stale preview, then delete for real.
            st, dp1 = http_post(base, "/api/v1/ingest/domains/alt.test/delete-preview", None, token=args.token)
            check("domain deletion preview reports the plan and a revalidation token",
                  st == 200 and dp1.get("delete_nodes") == len(ALT["nodes"]) and dp1.get("token"), dp1)

            http_post(base, "/api/v1/ingest?domain=alt.test", ALT_EXTRA, token=args.token)
            st_stale, _ = http_delete(
                base, "/api/v1/ingest/domains/alt.test?confirm=true&token=" + str(dp1.get("token")), token=args.token)
            check("a stale deletion preview is rejected instead of deleting", st_stale == 409, {"status": st_stale})

            st, dp2 = http_post(base, "/api/v1/ingest/domains/alt.test/delete-preview", None, token=args.token)
            st_del, dres = http_delete(
                base, "/api/v1/ingest/domains/alt.test?confirm=true&token=" + str(dp2.get("token")), token=args.token)
            check("domain deletion removes only the selected domain's data",
                  st_del == 200 and dres.get("deleted_nodes") == len(ALT["nodes"]) + 1, dres)
            st, g2 = http_get(base, "/api/v1/graph")
            ids2 = {n["id"] for n in g2["nodes"]}
            check("the other domain survives a scoped deletion",
                  ALT_S not in ids2 and ALT_Z not in ids2 and USER in ids2 and len(ids2) == len(present["nodes"]),
                  {"alt_left": sorted(ids2 & {ALT_S, ALT_M, ALT_T, ALT_X, ALT_Y, ALT_Z}), "total": len(ids2)})
            st_noauth, _ = http_post(base, "/api/v1/ingest/domains/uxlab.test/delete-preview", None, token=None)
            check("ingestion-management endpoints require the write token",
                  st_noauth in (401, 403), {"status": st_noauth})
        else:
            skip("domain-scoped ingestion + management", "no --token or fixture")

        # ---- 14/15. data management: replace-mode ingest + delete ----------
        if args.token:
            # Server-side guards first (these must not mutate anything).
            st_noauth, _ = http_delete(base, "/api/v1/graph?confirm=true", token=None)
            check("clear API rejects a request without a token",
                  st_noauth in (401, 403), {"status": st_noauth})
            st_noconf, nbody = http_delete(base, "/api/v1/graph", token=args.token)
            check("clear API requires an explicit confirmation",
                  st_noconf == 400 and "confirm" in json.dumps(nbody).lower(),
                  {"status": st_noconf, "body": nbody})
            st_badmode, _ = http_post(base, "/api/v1/ingest?mode=wipe", FIXTURE, token=args.token)
            check("ingest rejects an unknown mode instead of guessing",
                  st_badmode == 400, {"status": st_badmode})
            check("a rejected mode/confirmation leaves the graph intact",
                  http_get(base, "/api/v1/stats")[1].get("nodes") == len(present["nodes"]))

            # The UI must expose both controls, defaulting to merge.
            d.execute_script("arguments[0].click();",
                             d.find_element(By.CSS_SELECTOR, '.nav-btn[data-view="ingestion"]'))
            WebDriverWait(d, 10).until(lambda x: "view-ingestion" in js(x, "return (document.querySelector('.view.active')||{}).id||''"))
            ctl = js(d, """return {replace: document.getElementById('ingestReplace')!==null,
                defaultOff: document.getElementById('ingestReplace') && !document.getElementById('ingestReplace').checked,
                del: document.getElementById('clearGraph')!==null,
                status: document.getElementById('clearStatus').textContent};""")
            check("ingestion view exposes a replace toggle (off by default) and a delete control",
                  ctl["replace"] and ctl["defaultOff"] and ctl["del"] and "nodes" in ctl["status"], ctl)

            # Replace-mode ingest through the actual file picker.
            tmp = os.path.join(tempfile.gettempdir(), "omenhound_ux_mini.json")
            with open(tmp, "w") as fh:
                json.dump(MINI, fh)
            js(d, "window.confirm = () => true;")
            d.find_element(By.ID, "ingestFile").send_keys(tmp)
            d.execute_script("document.getElementById('ingestToken').value=arguments[0];", args.token)
            d.execute_script("document.getElementById('ingestReplace').checked=true;")
            d.execute_script("arguments[0].click();", d.find_element(By.ID, "ingestSubmit"))
            WebDriverWait(d, 20).until(lambda x: js(x, "return nodes.length===1 && byId.has('UX-MINI-1')"))
            repl = js(d, "return {n:nodes.length, hasOld:byId.has('%s'), status:document.getElementById('ingestStatus').textContent}" % USER)
            check("replace-mode ingest keeps only the uploaded graph",
                  repl["n"] == 1 and repl["hasOld"] is False, repl)

            # Seed analysis state so the reset is observable, then delete via the UI.
            js(d, """startNodeId=nodes[0].id; targetNodeId=nodes[0].id;
                pathHighlight={nodes:new Set([nodes[0].id]),edges:new Set(),length:0};
                selectNode(nodes[0]); updateStartUI();""")
            d.execute_script("arguments[0].click();", d.find_element(By.ID, "clearGraph"))
            WebDriverWait(d, 20).until(lambda x: js(x, "return nodes.length===0"))
            cleared = js(d, """return {n:nodes.length, e:edges.length,
                status:document.getElementById('clearStatus').textContent,
                start:startNodeId, target:targetNodeId, path:pathHighlight, sel:selectedNode};""")
            check("deleting all data empties the graph and resets analysis state",
                  cleared["n"] == 0 and cleared["e"] == 0 and cleared["start"] is None and
                  cleared["target"] is None and cleared["path"] is None and cleared["sel"] is None,
                  cleared)
            sst, sstats = http_get(base, "/api/v1/stats")
            check("the server reports an empty graph after deletion",
                  sst == 200 and sstats.get("nodes") == 0 and sstats.get("edges") == 0, sstats)

            # Leave the scratch server usable again.
            rst, rresp = http_post(base, "/api/v1/ingest?mode=replace", FIXTURE, token=args.token)
            check("replace-mode ingest restores exactly one dataset",
                  rst == 200 and (rresp.get("stats") or {}).get("nodes") == len(FIXTURE["nodes"]),
                  {"status": rst, "resp": rresp})
        else:
            skip("clear API token/confirmation guards", "no --token supplied")
            skip("replace-mode ingest keeps only the uploaded graph", "no --token supplied")
            skip("deleting all data empties the graph", "no --token supplied")

        # ---- console cleanliness --------------------------------------
        errs = js(d, "return window.__errs || []")
        log = [e for e in d.get_log("browser") if e["level"] == "SEVERE"]
        check("no uncaught JS errors or severe console messages", len(errs) == 0 and len(log) == 0,
              {"errs": errs, "log": [e["message"][:120] for e in log]})
    finally:
        d.quit()

    p = sum(1 for s, _, _ in RESULTS if s == "pass")
    f = sum(1 for s, _, _ in RESULTS if s == "fail")
    s = sum(1 for st, _, _ in RESULTS if st == "skip")
    print("\n==== %d passed, %d failed, %d skipped ====" % (p, f, s))
    return 0 if f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
