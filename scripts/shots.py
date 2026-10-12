#!/usr/bin/env python3
"""Capture OmenHound WebUI screenshots for the wiki (Selenium + local Chromium).

Three shots into <outdir>:
  webui-graph.png    - the force-directed attack-path graph
  webui-abuse.png    - an edge selected: dynamic abuse command + OPSEC
  webui-authgate.png - the write-API token gate, showing a real 401 on a bad token

Usage: scripts/shots.py [base-url] [outdir]
"""
import json
import os
import sys
import time
import urllib.request

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18091"
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "..", "docs", "wiki", "img")
OUT = os.path.abspath(OUT)

SELECT_EDGE_JS = """
const pref = ['DCSync','GenericAll','AdminTo','GenericWrite','HasSession','MemberOf'];
let e = null;
for (const k of pref) { e = edges.find(x => x.kind === k); if (e) break; }
if (!e) return null;
const a = toScreen(byId.get(e.source)), b = toScreen(byId.get(e.target));
const r = canvas.getBoundingClientRect();
const x = r.left + (a.x + b.x) / 2, y = r.top + (a.y + b.y) / 2;
const fire = (t, buttons) => canvas.dispatchEvent(new PointerEvent(t, {
  clientX: x, clientY: y, bubbles: true, pointerId: 1, pointerType: 'mouse', button: 0, buttons,
}));
fire('pointerdown', 1); fire('pointerup', 0);
return e.kind;
"""


def main():
    os.makedirs(OUT, exist_ok=True)
    with urllib.request.urlopen(BASE + "/api/v1/health", timeout=5) as r:
        print("health:", r.read().decode())

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1600,900")
    opts.add_argument("--force-device-scale-factor=2")
    opts.add_argument("--hide-scrollbars")
    opts.binary_location = "/usr/bin/chromium"
    driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=opts)
    try:
        driver.get(BASE + "/")
        wait = WebDriverWait(driver, 30)
        wait.until(lambda d: d.execute_script("return typeof nodes !== 'undefined' && nodes.length > 0"))
        time.sleep(6)  # let the force layout settle

        # 1) graph
        graph_png = os.path.join(OUT, "webui-graph.png")
        driver.save_screenshot(graph_png)
        print("wrote", graph_png)

        # 2) abuse panel via a real click on an edge
        kind = driver.execute_script(SELECT_EDGE_JS)
        print("selected edge:", kind)
        wait.until(lambda d: "loading" not in d.find_element(By.ID, "edge-command").text)
        time.sleep(1)
        abuse_png = os.path.join(OUT, "webui-abuse.png")
        driver.save_screenshot(abuse_png)
        print("wrote", abuse_png)

        # 3) auth gate + real 401
        driver.find_element(By.ID, "push").click()
        wait.until(EC.visibility_of_element_located((By.ID, "gate")))
        driver.find_element(By.ID, "gate-token").send_keys("wrong-token")
        driver.find_element(By.ID, "gate-json").send_keys('{"nodes":[{"id":"demo","kind":"User","name":"demo"}],"edges":[]}')
        driver.find_element(By.ID, "gate-push").click()
        wait.until(lambda d: d.find_element(By.ID, "gate-status").text.startswith("denied"))
        time.sleep(0.5)
        gate_png = os.path.join(OUT, "webui-authgate.png")
        driver.save_screenshot(gate_png)
        print("wrote", gate_png, "|", driver.find_element(By.ID, "gate-status").text)
    finally:
        driver.quit()


if __name__ == "__main__":
    main()
