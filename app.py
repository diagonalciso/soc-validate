#!/usr/bin/env python3
"""soc-validate — detection validation / purple-team runner.

Bundles the Atomic Red Team atomics (git submodule `atomics/`, MIT). Fires a
chosen ATT&CK technique's Linux (sh/bash) atomic, then queries soc-ops for a
matching alert in a time window → PASS (detected) / ACTIVITY (new alert, no
technique match) / BLIND (nothing). Builds a coverage heatmap.

SAFETY: execution is OFF by default (dry-run resolves the command but does not
run it). Set EXECUTION_ENABLED=1 AND pass confirm=1 per run to actually execute,
and only sh/bash Linux atomics run. Scope this at a lab endpoint, never prod.

Deps: PyYAML. Run: cp .env.example .env && python3 app.py  (:8104)
"""
import glob
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen

import yaml

ATOMICS_DIR = os.getenv("ATOMICS_DIR", os.path.join(os.path.dirname(__file__), "atomics", "atomics"))
DB_PATH = os.getenv("VAL_DB", os.path.join(os.path.dirname(__file__), "validate.db"))
PORT = int(os.getenv("VAL_PORT", "8104"))
HOST = os.getenv("VAL_HOST", "0.0.0.0")
SOC_OPS_URL = os.getenv("SOC_OPS_URL", "http://localhost:8081").rstrip("/")
EXECUTION_ENABLED = os.getenv("EXECUTION_ENABLED", "0") == "1"
RUN_TIMEOUT = int(os.getenv("RUN_TIMEOUT", "60"))
DETECT_WINDOW = int(os.getenv("DETECT_WINDOW", "45"))   # seconds to wait/scan for an alert

_lock = threading.Lock()
_index = {}          # technique_id -> {display_name, tests:[...linux sh/bash only...]}
_state = {"ready": False, "count": 0}


def _init_db():
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, technique TEXT, name TEXT,
        guid TEXT, executed INTEGER, verdict TEXT, detail TEXT)""")
    c.commit()
    c.close()


def _linux_tests(doc):
    out = []
    for t in doc.get("atomic_tests", []) or []:
        plats = t.get("supported_platforms", []) or []
        ex = t.get("executor", {}) or {}
        if "linux" in plats and ex.get("name") in ("sh", "bash") and ex.get("command"):
            args = {k: (v or {}).get("default", "") for k, v in
                    (t.get("input_arguments") or {}).items()}
            out.append({
                "name": t.get("name", ""),
                "guid": t.get("auto_generated_guid", ""),
                "description": (t.get("description", "") or "").strip(),
                "executor": ex.get("name"),
                "command": ex.get("command", ""),
                "cleanup": ex.get("cleanup_command", ""),
                "args": args,
                "elevation": bool(ex.get("elevation_required")),
            })
    return out


def _build_index():
    idx = {}
    for path in glob.glob(os.path.join(ATOMICS_DIR, "T*", "T*.yaml")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        tests = _linux_tests(doc)
        if not tests:
            continue
        tid = doc.get("attack_technique", os.path.basename(path).split(".yaml")[0])
        idx[tid] = {"technique": tid,
                    "display_name": doc.get("display_name", tid),
                    "tests": tests}
    with _lock:
        _index.clear()
        _index.update(idx)
        _state["ready"] = True
        _state["count"] = len(idx)


def _resolve(cmd, args):
    for k, v in args.items():
        cmd = cmd.replace("#{%s}" % k, str(v))
    return cmd


# --------------------------------------------------------------------------- #
# Detection check — query soc-ops for a matching alert in the window
# --------------------------------------------------------------------------- #
def _fetch_alerts(per=50):
    try:
        with urlopen(f"{SOC_OPS_URL}/api/alerts?per={per}", timeout=3) as r:
            data = json.loads(r.read())
        # soc-ops may wrap in {"alerts":[...]} or return a bare list
        if isinstance(data, dict):
            return data.get("alerts") or data.get("items") or []
        return data if isinstance(data, list) else []
    except Exception:
        return None


def _detect(technique, since_epoch):
    """Return (verdict, detail). Best-effort against soc-ops."""
    deadline = time.time() + DETECT_WINDOW
    tid = technique.lower()
    base = tid.split(".")[0]
    while time.time() < deadline:
        alerts = _fetch_alerts()
        if alerts is None:
            return "UNKNOWN", "soc-ops unreachable"
        blob = json.dumps(alerts).lower()
        # technique-id match anywhere in recent alerts = strong signal
        if tid in blob or base in blob:
            return "PASS", f"technique {technique} referenced in a recent alert"
        time.sleep(3)
    # final: did ANY new alert appear after we started?
    alerts = _fetch_alerts() or []
    fresh = 0
    for a in alerts:
        ts = str(a.get("timestamp") or a.get("ts") or "")
        try:
            e = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            if e >= since_epoch - 2:
                fresh += 1
        except Exception:
            continue
    if fresh:
        return "ACTIVITY", f"{fresh} new alert(s) in window but no technique match"
    return "BLIND", "no alert observed in window"


def _run_atomic(technique, guid, do_execute):
    entry = _index.get(technique)
    if not entry:
        return {"error": "unknown technique"}
    test = next((t for t in entry["tests"] if t["guid"] == guid), None)
    if not test:
        return {"error": "unknown atomic guid"}
    resolved = _resolve(test["command"], test["args"])
    started = time.time()
    executed = False
    output = ""
    verdict, detail = "DRYRUN", "execution disabled (dry-run)"

    if do_execute:
        if not EXECUTION_ENABLED:
            detail = "EXECUTION_ENABLED=0 — refusing to run; showing resolved command only"
        else:
            executed = True
            try:
                p = subprocess.run(["/bin/sh", "-c", resolved], capture_output=True,
                                   text=True, timeout=RUN_TIMEOUT)
                output = (p.stdout or "") + (p.stderr or "")
                output = output[-4000:]
            except subprocess.TimeoutExpired:
                output = "(timed out)"
            except Exception as e:
                output = f"(run error: {e})"
            verdict, detail = _detect(technique, started)

    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "technique": technique, "name": test["name"], "guid": guid,
           "executed": executed, "verdict": verdict, "detail": detail,
           "resolved_command": resolved, "output": output}
    c = sqlite3.connect(DB_PATH)
    c.execute("INSERT INTO runs (ts,technique,name,guid,executed,verdict,detail) "
              "VALUES (?,?,?,?,?,?,?)",
              (rec["ts"], technique, test["name"], guid, int(executed), verdict, detail))
    c.commit()
    c.close()
    return rec


def _last_verdicts():
    c = sqlite3.connect(DB_PATH)
    rows = c.execute("SELECT technique, verdict FROM runs WHERE executed=1 "
                     "ORDER BY id").fetchall()
    c.close()
    last = {}
    for tech, verdict in rows:
        last[tech] = verdict
    return last


def _stats():
    with _lock:
        techs = list(_index.values())
    last = _last_verdicts()
    tested = len(last)
    passed = sum(1 for v in last.values() if v == "PASS")
    blind = sum(1 for v in last.values() if v == "BLIND")
    return {"ready": _state["ready"], "techniques": len(techs),
            "atomics": sum(len(t["tests"]) for t in techs),
            "tested": tested, "detected": passed, "blind": blind,
            "coverage_pct": round(100 * passed / len(techs), 1) if techs else 0,
            "execution_enabled": EXECUTION_ENABLED, "soc_ops": SOC_OPS_URL}


def _matrix(q):
    text = (q.get("q", [""])[0] or "").lower()
    last = _last_verdicts()
    with _lock:
        techs = sorted(_index.values(), key=lambda x: x["technique"])
    out = []
    for t in techs:
        if text and text not in t["technique"].lower() and text not in t["display_name"].lower():
            continue
        out.append({"technique": t["technique"], "display_name": t["display_name"],
                    "atomics": len(t["tests"]), "verdict": last.get(t["technique"], "UNTESTED")})
    return out


PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Soc-Validate — Purple-Team Detection Validation</title><style>
:root{--bg:#0d1117;--panel:#161b22;--bd:#30363d;--txt:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--pass:#3fb950;--blind:#f85149;--act:#d29922;--unt:#21262d}
*{box-sizing:border-box}body{margin:0;font-family:'JetBrains Mono',ui-monospace,monospace;background:var(--bg);color:var(--txt)}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;border-bottom:1px solid var(--bd);background:var(--panel)}
h1{margin:0;font-size:18px;letter-spacing:1px;color:var(--accent)}h1 small{font-weight:400;opacity:.55;font-size:.6em;color:var(--txt)}
.meta{font-size:12px;color:var(--dim);text-align:right}
.wrap{max-width:1300px;margin:0 auto;padding:18px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:14px}
.kpi{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:12px}
.kpi .n{font-size:23px;font-weight:700;color:var(--accent)}.kpi .l{font-size:11px;color:var(--dim);text-transform:uppercase}
.warn{background:#2a1a00;border:1px solid #5a3a00;color:var(--act);padding:9px 12px;border-radius:8px;margin-bottom:12px;font-size:12px}
input{background:#0a1020;border:1px solid var(--bd);color:var(--txt);padding:7px 9px;border-radius:6px;font-family:inherit;width:280px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:7px;margin-top:12px}
.cell{border:1px solid var(--bd);border-radius:6px;padding:8px;font-size:11px;cursor:pointer}
.cell:hover{border-color:var(--accent)}
.cell .t{font-weight:700}.cell .d{color:var(--dim);font-size:10px;overflow:hidden;height:26px}
.PASS{background:rgba(63,185,80,.14);border-color:var(--pass)}.BLIND{background:rgba(248,81,73,.14);border-color:var(--blind)}
.ACTIVITY{background:rgba(210,153,34,.14);border-color:var(--act)}.UNKNOWN{background:rgba(139,148,158,.12)}
.UNTESTED{}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;padding:20px;z-index:10}
.modal .box{background:var(--panel);border:1px solid var(--accent);border-radius:10px;max-width:760px;width:100%;max-height:88vh;overflow:auto;padding:18px}
button{background:var(--accent);color:#fff;border:none;border-radius:6px;padding:8px 14px;cursor:pointer;font-family:inherit;margin-right:8px}
button.ghost{background:#1a2440;color:var(--txt)}
pre{background:#0a1020;border:1px solid var(--bd);border-radius:6px;padding:10px;overflow:auto;font-size:11px;max-height:220px;white-space:pre-wrap}
select{background:#0a1020;border:1px solid var(--bd);color:var(--txt);padding:6px;border-radius:6px;font-family:inherit;width:100%;margin:6px 0}
.legend span{font-size:10px;margin-right:10px}
</style></head><body>
<header><h1>SOC-VALIDATE <small>purple team · Atomic Red Team</small></h1>
<div class="meta" id="meta">loading…</div></header>
<div class="wrap">
  <div id="execwarn"></div>
  <div class="kpis">
    <div class="kpi"><div class="n" id="k-tech">--</div><div class="l">Techniques (linux)</div></div>
    <div class="kpi"><div class="n" id="k-atom">--</div><div class="l">Atomics</div></div>
    <div class="kpi"><div class="n" id="k-tested">--</div><div class="l">Tested</div></div>
    <div class="kpi"><div class="n" id="k-det">--</div><div class="l">Detected</div></div>
    <div class="kpi"><div class="n" id="k-cov">--</div><div class="l">Coverage</div></div>
  </div>
  <input id="q" placeholder="filter technique id / name…" oninput="reload()">
  <span class="legend" style="margin-left:12px">
    <span style="color:var(--pass)">■ detected</span><span style="color:var(--act)">■ activity</span>
    <span style="color:var(--blind)">■ blind</span><span style="color:var(--dim)">■ untested</span></span>
  <div class="grid" id="grid"></div>
</div>
<div class="modal" id="modal"><div class="box" id="mbox"></div></div>
<script>
const $=s=>document.querySelector(s);
async function stats(){
  const s=await (await fetch('/api/stats')).json();
  $('#k-tech').textContent=s.techniques;$('#k-atom').textContent=s.atomics;
  $('#k-tested').textContent=s.tested;$('#k-det').textContent=s.detected;$('#k-cov').textContent=s.coverage_pct+'%';
  $('#meta').innerHTML='soc-ops: '+s.soc_ops+'<br>'+(s.ready?'ready':'indexing…');
  $('#execwarn').innerHTML = s.execution_enabled
    ? '<div class="warn" style="color:var(--blind);border-color:var(--blind)">⚠ EXECUTION ENABLED — atomics will actually run on this host. Scope to a lab endpoint.</div>'
    : '<div class="warn">Safe mode: EXECUTION_ENABLED=0. Runs are dry-run (resolved command shown, not executed). Set env to enable.</div>';
  if(!s.ready)setTimeout(stats,1500);
}
async function reload(){
  const rows=await (await fetch('/api/matrix?q='+encodeURIComponent($('#q').value))).json();
  $('#grid').innerHTML=rows.map(r=>`<div class="cell ${r.verdict}" onclick="open_t('${r.technique}')">
    <div class="t">${r.technique} <span style="float:right;font-size:9px">${r.verdict==='UNTESTED'?'':r.verdict}</span></div>
    <div class="d">${esc(r.display_name)}</div>
    <div style="color:var(--dim);font-size:9px">${r.atomics} atomic(s)</div></div>`).join('');
}
async function open_t(tid){
  const d=await (await fetch('/api/technique?id='+tid)).json();
  $('#mbox').innerHTML=`<div style="display:flex;justify-content:space-between">
    <b>${d.technique} — ${esc(d.display_name)}</b><button class="ghost" onclick="closeM()">✕</button></div>
    <select id="atomsel">${d.tests.map((t,i)=>`<option value="${i}">${esc(t.name)}</option>`).join('')}</select>
    <div id="atomdetail"></div>`;
  window._tests=d.tests;window._tid=d.technique;showAtom();
  $('#atomsel').onchange=showAtom;$('#modal').style.display='flex';
}
function showAtom(){
  const t=window._tests[$('#atomsel').value];
  $('#atomdetail').innerHTML=`<p style="font-size:12px;color:var(--dim)">${esc(t.description)}</p>
    <div>executor: <b>${t.executor}</b>${t.elevation?' <span style="color:var(--act)">(elevation)</span>':''}</div>
    <div style="font-size:11px;color:var(--dim)">resolved command:</div>
    <pre>${esc(t.command_resolved)}</pre>
    <button onclick="run(0)">Dry-run</button>
    <button onclick="run(1)" ${window._exec?'':'disabled title="EXECUTION_ENABLED=0"'}>Execute + check detection</button>
    <div id="runout"></div>`;
}
async function run(exec){
  const t=window._tests[$('#atomsel').value];
  $('#runout').innerHTML='<div style="color:var(--dim)">running…</div>';
  const p=new URLSearchParams({id:window._tid,guid:t.guid,execute:exec,confirm:exec});
  const r=await (await fetch('/api/run?'+p,{method:'POST'})).json();
  $('#runout').innerHTML=`<div>verdict: <b class="${r.verdict}">${r.verdict}</b> — ${esc(r.detail)}</div>
    ${r.output?'<pre>'+esc(r.output)+'</pre>':''}`;
  stats();reload();
}
function closeM(){$('#modal').style.display='none';}
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
fetch('/api/stats').then(r=>r.json()).then(s=>{window._exec=s.execution_enabled;});
stats();reload();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", PAGE)
        elif u.path == "/api/stats":
            self._send(200, "application/json", json.dumps(_stats()))
        elif u.path == "/api/matrix":
            self._send(200, "application/json", json.dumps(_matrix(q)))
        elif u.path == "/api/technique":
            entry = _index.get(q.get("id", [""])[0])
            if not entry:
                return self._send(404, "application/json", json.dumps({"error": "not found"}))
            tests = [{**t, "command_resolved": _resolve(t["command"], t["args"])}
                     for t in entry["tests"]]
            self._send(200, "application/json", json.dumps(
                {"technique": entry["technique"], "display_name": entry["display_name"],
                 "tests": tests}))
        elif u.path == "/health":
            self._send(200, "application/json", json.dumps(
                {"status": "ok", "ready": _state["ready"], "techniques": _state["count"]}))
        else:
            self._send(404, "text/plain", "not found")

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/api/run":
            tid = q.get("id", [""])[0]
            guid = q.get("guid", [""])[0]
            do_exec = q.get("execute", ["0"])[0] == "1" and q.get("confirm", ["0"])[0] == "1"
            self._send(200, "application/json", json.dumps(_run_atomic(tid, guid, do_exec)))
        else:
            self._send(404, "text/plain", "not found")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    _init_db()
    threading.Thread(target=_build_index, daemon=True).start()
    print(f"soc-validate on http://{HOST}:{PORT}  (execution={'ON' if EXECUTION_ENABLED else 'OFF'})")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
