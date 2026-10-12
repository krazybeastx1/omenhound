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
    ],
    "edges": [
        {"source": USER, "target": GROUP, "kind": "MemberOf"},
        {"source": GROUP, "target": GPO, "kind": "GenericAll"},
        {"source": USER, "target": HOST, "kind": "HasSession"},
        {"source": USER2, "target": HOST, "kind": "HasSession"},
    ],
    "meta": {"collector": "ux-fixture", "domain": "uxlab.test"},
}


def http_get(base, path, token=None):
    req = urllib.request.Request(base.rstrip("/") + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, json.loads(r.read().decode())


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
