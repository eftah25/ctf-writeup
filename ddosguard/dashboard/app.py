"""
FastAPI web dashboard for the DDoS guard.

Runs alongside the monitor in a single process (so it sees live state) and
also serves the persisted JSONL history files.  Endpoints:

    GET  /                            -> dashboard page
    GET  /api/status                  -> monitor state snapshot
    GET  /api/stats?window=N         -> rolling window statistics
    GET  /api/baseline               -> baseline model summary
    GET  /api/alerts                 -> alert timeline
    GET  /api/mitigations            -> active mitigation actions
    GET  /api/whitelist              -> current whitelist
    POST /api/whitelist              -> add/remove an IP
    POST /api/rate-limit             -> override the per-IP rate limiter
    POST /api/mitigate               -> trigger a stage manually
    POST /api/mitigations/clear      -> clear active mitigation actions
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from ..config import Config
from ..core import MigrationAction, PacketRecord, TrafficStats, WhitelistedIp
from ..metrics.window import RollingAggregator
from ..monitor import MonitorState

app = FastAPI(title="DDoS Mitigation Dashboard")

# ---- static assets ----------------------------------------------------- #
_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
else:
    _STATIC_DIR = None


# ---- in-memory monitor state (populated by the monitor runner) -------- #
state: MonitorState = MonitorState()


def _load_history(path: str):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


# ---- page -------------------------------------------------------------- #
@app.get("/")
def index(request: Request):
    html = _load_html()
    return HTMLResponse(html)


# ---- state ------------------------------------------------------------- #
@app.get("/api/status")
def api_status():
    return JSONResponse(state.snapshot())


# ---- statistics ---------------------------------------------------------- #
@app.get("/api/stats")
def api_stats(window: int = 1, limit: int = 20):
    if state.stats is not None:
        return JSONResponse(state.stats.tail(limit).to_dict())
    return JSONResponse({"windows": []})


# ---- baseline ------------------------------------------------------------ #
@app.get("/api/baseline")
def api_baseline():
    return JSONResponse({"models": state.baseline.all() if state.baseline else []})


# ---- alerts ---------------------------------------------------------------- #
@app.get("/api/alerts")
def api_alerts(limit: int = 100):
    return JSONResponse({"alerts": state.alerts.get_timeline(limit)})


# ---- mitigations ----------------------------------------------------------- #
@app.get("/api/mitigations")
def api_mitigations():
    return JSONResponse({"actions": state.mitigations.actions()})


# ---- whitelist ------------------------------------------------------------- #
@app.get("/api/whitelist")
def api_whitelist():
    return JSONResponse({"ips": state.whitelist.list()})

@app.post("/api/whitelist")
def api_whitelist_add(payload: dict):
    ip = (payload.get("ip") or "").strip()
    if not ip:
        raise HTTPException(400, "ip is required")
    state.whitelist.add(ip, payload.get("reason", "admin"))
    return JSONResponse(state.whitelist.list())

@app.post("/api/whitelist/remove")
def api_whitelist_remove(payload: dict):
    ip = (payload.get("ip") or "").strip()
    if not ip:
        raise HTTPException(400, "ip is required")
    state.whitelist.remove(ip)
    return JSONResponse(state.whitelist.list())

# ---- rate limiter override ------------------------------------------- #
@app.post("/api/rate-limit")
def api_rate_limit(payload: dict):
    key = (payload.get("key") or "").strip()
    rate = int(payload.get("rate", 0))
    burst = int(payload.get("burst", 0))
    if not key or rate <= 0:
        raise HTTPException(400, "key and rate > 0 required")
    state.mitigations.update_buckets(key, rate, burst)
    return JSONResponse({"ok": True, "bucket_tokens": state.mitigations.tokens(key)})

# ---- manual mitigation trigger ------------------------------- #
@app.post("/api/mitigate")
def api_mitigate(payload: dict):
    stage = int(payload.get("stage", 0))
    if stage < 0 or stage > 4:
        raise HTTPException(400, "stage must be 0..4")
    state.mitigations.set_active_stage(stage)
    return JSONResponse({"ok": True, "stage": stage})

# ---- clear active mitigation --------------------------------------- #
@app.post("/api/mitigations/clear")
def api_clear_mitigations():
    state.mitigations.clear_actions()
    return JSONResponse({"ok": True})

# ---- control helpers (pause/resume) ------------------------------ #
@app.post("/api/control/pause")
def api_pause():
    state.pause()
    return JSONResponse({"ok": True})

@app.post("/api/control/resume")
def api_resume():
    state.resume()
    return JSONResponse({"ok": True})


# ---- internal helpers ------------------------------------------------------ #
def _load_html() -> str:
    if _STATIC_DIR and os.path.isdir(_STATIC_DIR):
        with open(os.path.join(_STATIC_DIR, "index.html"), "r", encoding="utf-8") as fh:
            return fh.read()
    return OPENAI_README


OPENAI_README = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DDoS Mitigation Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; }
  .time { color: #6b7280; font-size: 0.8rem; }
  .spark { height: 60px; }
  .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; }
  .stage-pill { min-width: 72px; text-align: center; }
</style>
</head>
<body class="p-4">
  <h1 class="text-2xl font-bold mb-3">DDoS Mitigation Dashboard</h1>
  <div class="flex gap-4 flex-wrap">
    <div class="card w-64">
      <div class="text-sm text-gray-500">Time</div>
      <div id="now" class="time">--</div>
      <div class="text-sm text-gray-500 mt-2">Overall score</div>
      <div id="score" class="text-xl font-bold">--</div>
      <div class="text-sm text-gray-500 mt-2">Severity</div>
      <div id="severity" class="text-lg font-bold">--</div>
    </div>
    <div class="card w-64">
      <div class="text-sm text-gray-500">Packet rate (pps)</div>
      <div id="pkts" class="text-xl font-bold">--</div>
      <div class="text-sm text-gray-500">Byte rate (B/s)</div>
      <div id="bytes" class="text-xl font-bold">--</div>
      <div class="text-sm text-gray-500">Unique sources</div>
      <div id="sources" class="text-xl font-bold">--</div>
    </div>
    <div class="card w-64">
      <div class="text-sm text-gray-500">Protocol distribution</div>
      <div id="proto-bar" class="text-xs">--</div>
      <div class="text-sm text-gray-500 mt-2">Top destination ports</div>
      <div id="top-ports" class="text-xs">--</div>
    </div>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4">
    <div class="card">
      <div class="text-sm font-semibold mb-2">Traffic timeline (packets/s)</div>
      <canvas id="timeline" class="w-full h-40"></canvas>
    </div>
    <div class="card">
      <div class="text-sm font-semibold mb-2">Alert timeline</div>
      <div id="alert-list" class="max-h-64 overflow-auto space-y-1 text-xs"></div>
    </div>
  </div>
  <div class="mt-4 card">
    <div class="text-sm font-semibold mb-2">Active mitigations</div>
    <div id="mitigations" class="text-xs"></div>
  </div>
  <div class="mt-4 card flex flex-wrap gap-2 items-end">
    <div class="flex-1">
      <label class="block text-xs mb-1">Add IP to whitelist</label>
      <div class="flex gap-2">
        <input id="ip-input" class="border rounded px-2 py-1 flex-1" placeholder="10.0.0.1">
        <button id="add-ip" class="bg-emerald-600 hover:bg-emerald-700 text-white rounded px-3 py-1 text-sm">Allow</button>
      </div>
    </div>
    <div class="flex-1">
      <label class="block text-xs mb-1">Trigger mitigation stage 0..4</label>
      <div class="flex gap-2">
        <input id="stage-input" class="border rounded px-2 py-1 w-full" placeholder="stage">
        <button id="set-stage" class="bg-blue-600 hover:bg-blue-700 text-white rounded px-3 py-1 text-sm">Set</button>
      </div>
    </div>
  </div>
  <script>
    const state = { state };
    async function api(path, opts) {
      const r = await fetch(path, opts);
      const j = await r.json();
      return j;
    }
    async function refresh() {
      const [s, stats, alerts, mit, wl] = await Promise.all([
        api('/api/status'), api('/api/stats'), api('/api/alerts'), api('/api/mitigations'), api('/api/whitelist')
      ]);
      document.getElementById('now').textContent = new Date().toLocaleTimeString();
      document.getElementById('score').textContent = s.overall?.total ?? '--';
      document.getElementById('severity').textContent = s.overall?.severity ?? '--';
      document.getElementById('pkts').textContent = (stats.last?.packet_rate ?? '--').toFixed(1);
      document.getElementById('bytes').textContent = (stats.last?.byte_rate ?? '--').toFixed(0);
      document.getElementById('sources').textContent = stats.last?.unique_sources ?? '--';
      document.getElementById('mitigations').textContent = JSON.stringify(mit.actions ?? [], null, 2);
      const list = document.getElementById('alert-list');
      list.innerHTML = (alerts.alerts ?? []).slice(-8).reverse().map(a =>
        `<div class="p-1 ${a.severity === 'CRITICAL' ? 'bg-red-100' : a.severity === 'HIGH' ? 'bg-orange-100' : 'bg-gray-100'} rounded">${a.title} ${a.severity}</div>`
      ).join('');
      const t = document.getElementById('timeline');
      t.getContext('2d').clearRect(0, 0, t.width, t.height);
      t.width = t.clientWidth;
      t.height = t.clientHeight;
      const dpr = window.devicePixelRatio || 1;
      t.width *= dpr; t.height *= dpr;
      t.style.width = t.clientWidth + 'px'; t.style.height = t.clientHeight + 'px';
      const ctx = t.getContext('2d');
      ctx.scale(dpr, dpr);
      const w = t.width; const h = t.height;
      const data = stats.windows ?? [];
      if (data.length > 1) {
        ctx.beginPath();
        ctx.strokeStyle = '#2563eb';
        ctx.lineWidth = 2;
        data.forEach((d, i) => {
          const x = (i / (data.length - 1)) * w;
          const y = h - (d.packet_rate / 200) * (h - 20) - 10;
          i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
        });
        ctx.stroke();
      }
    }
    document.getElementById('add-ip').onclick = async () => {
      const ip = document.getElementById('ip-input').value.trim();
      if (!ip) return;
      await api('/api/whitelist', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip, reason: 'dashboard'}) });
      document.getElementById('ip-input').value = '';
      refresh();
    };
    document.getElementById('set-stage').onclick = async () => {
      const s = parseInt(document.getElementById('stage-input').value, 10);
      if (Number.isNaN(s)) return;
      await api('/api/mitigate', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({stage: s}) });
      refresh();
    };
    setInterval(refresh, 2000);
    refresh();
  </script>
</body>
</html>"""
