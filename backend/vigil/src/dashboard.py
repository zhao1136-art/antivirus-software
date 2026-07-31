"""
Local Flask dashboard at http://127.0.0.1:7331.

Panels:
  - Scan history          (logs/scan_log.jsonl)
  - Behavior alerts       (logs/behavior_log.jsonl)
  - Quarantine manager    (quarantine/*.quar + sidecar JSON) — restore / delete
  - Model info            (models/changelog.json — current versions + F1)

Refresh: client-side, every 10 s, by re-hitting the /api/* endpoints.

Run:
    python -m src.dashboard           # blocking
or via the unified launcher:
    python -m antivirus
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sys

from flask import Flask, jsonify, request, abort, render_template_string


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(HERE, "logs")
QUARANTINE_DIR = os.path.join(HERE, "quarantine")
MODELS_DIR = os.path.join(HERE, "models")
RESTORE_DIR = os.path.join(HERE, "restored")

SCAN_LOG = os.path.join(LOGS_DIR, "scan_log.jsonl")
BEHAVIOR_LOG = os.path.join(LOGS_DIR, "behavior_log.jsonl")
CHANGELOG = os.path.join(MODELS_DIR, "changelog.json")


# ---------- helpers ---------------------------------------------------------

def _tail_jsonl(path: str, n: int = 200) -> list[dict]:
    """Return the last N JSON lines of `path`, newest first."""
    if not os.path.isfile(path):
        return []
    out: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return list(reversed(out[-n:]))


def _list_quarantine() -> list[dict]:
    if not os.path.isdir(QUARANTINE_DIR):
        return []
    items: list[dict] = []
    for quar in sorted(glob.glob(os.path.join(QUARANTINE_DIR, "*.quar"))):
        sidecar = quar + ".json"
        meta: dict = {}
        if os.path.isfile(sidecar):
            try:
                with open(sidecar, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except (OSError, json.JSONDecodeError):
                meta = {"error": "sidecar read failed"}
        st = os.stat(quar)
        items.append({
            "id": os.path.basename(quar),
            "quarantine_path": quar,
            "sidecar_path": sidecar if os.path.isfile(sidecar) else None,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "original_path": meta.get("original_path"),
            "file_type": meta.get("file_type"),
            "verdict": meta.get("verdict"),
            "confidence": meta.get("confidence"),
            "reasons": meta.get("reasons", []),
        })
    return items


def _safe_quar_path(qid: str) -> str:
    """Resolve a quarantine ID safely back to its absolute on-disk path.

    Rejects anything that escapes the quarantine directory (path traversal)."""
    qid = os.path.basename(qid)  # strip any directory components
    quar = os.path.abspath(os.path.join(QUARANTINE_DIR, qid))
    qdir = os.path.abspath(QUARANTINE_DIR) + os.sep
    if not quar.startswith(qdir):
        abort(400, "bad quarantine id")
    if not os.path.isfile(quar):
        abort(404, "not found")
    return quar


# ---------- Flask app -------------------------------------------------------

app = Flask(__name__)


_INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Vigil — 仪表盘</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0e1116; color: #e4e6eb; margin: 0; padding: 24px; }
  h1 { margin-top: 0; font-size: 1.4rem; }
  h2 { font-size: 1.05rem; margin: 28px 0 8px; padding-bottom: 4px;
       border-bottom: 1px solid #2a2f3a; }
  .row { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  .panel { background: #161a22; border: 1px solid #232936; border-radius: 8px;
           padding: 14px 18px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { padding: 5px 8px; text-align: left;
           border-bottom: 1px solid #232936; vertical-align: top; }
  th { color: #8b95a7; font-weight: 600; }
  td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .v-clean { color: #62c97a; font-weight: 600; }
  .v-mal   { color: #ff7a7a; font-weight: 600; }
  .sev-high   { color: #ff7a7a; font-weight: 600; }
  .sev-medium { color: #f3c969; font-weight: 600; }
  .sev-low    { color: #8b95a7; font-weight: 600; }
  .pill { display: inline-block; padding: 1px 6px; border-radius: 4px;
          background: #232936; font-size: 0.75rem; }
  .vt-badge { display: inline-block; margin-left: 6px; padding: 1px 6px;
              border-radius: 4px; background: #3a2e14; color: #f3c969;
              border: 1px solid #5a4720; font-size: 0.72rem; font-weight: 600;
              text-decoration: none; vertical-align: middle; }
  .vt-badge:hover { background: #4a3a1a; }
  button { background: #2c3140; color: #e4e6eb; border: 1px solid #3a4153;
           border-radius: 4px; padding: 3px 8px; cursor: pointer; font-size: 0.8rem; }
  button:hover { background: #3a4153; }
  button.danger { color: #ff7a7a; border-color: #5a2e2e; }
  .muted { color: #8b95a7; font-size: 0.8rem; }
  .empty { color: #8b95a7; font-style: italic; padding: 8px 0; }
</style>
</head>
<body>
<h1>Vigil &mdash; 仪表盘 <span class="muted" id="updated">(更新中...)</span></h1>

<h2>模型信息</h2>
<div class="panel"><div id="model-info" class="empty">加载中...</div></div>

<div class="row">
  <div>
    <h2>扫描记录 <span class="muted" id="scan-count"></span></h2>
    <div class="panel"><div id="scan-table" class="empty">加载中...</div></div>
  </div>
  <div>
    <h2>行为告警 <span class="muted" id="behavior-count"></span></h2>
    <div class="panel"><div id="behavior-table" class="empty">加载中...</div></div>
  </div>
</div>

<h2>隔离区 <span class="muted" id="quar-count"></span></h2>
<div class="panel"><div id="quar-table" class="empty">加载中...</div></div>

<script>
function esc(s){ return String(s == null ? '' : s).replace(/[&<>"]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtConf(c){ return c == null ? '' : (Math.round(c * 10000) / 100) + '%'; }
function fmtTs(t){ if(!t) return ''; return new Date(t).toLocaleString(); }
function verdictClass(v){ return v === 'MALICIOUS' ? 'v-mal' : 'v-clean'; }

async function loadJSON(url){
  try { const r = await fetch(url); return await r.json(); }
  catch(e){ return null; }
}

function renderModels(data){
  const el = document.getElementById('model-info');
  if(!data || !data.models || !data.models.length){
    el.innerHTML = '<div class="empty">暂无模型 &mdash; 请运行训练</div>';
    return;
  }
  let html = '<table><thead><tr><th>模型</th><th>当前版本</th><th>F1</th><th>版本记录</th><th>最后变更</th></tr></thead><tbody>';
  for(const m of data.models){
    html += `<tr>
      <td class="mono">${esc(m.name)}</td>
      <td>v${esc(m.current_version)}</td>
      <td>${m.f1 == null ? '' : esc(m.f1.toFixed(4))}</td>
      <td>${esc(m.versions_logged)}</td>
      <td class="muted">${esc(m.last_change || '')}</td>
    </tr>`;
  }
  el.innerHTML = html + '</tbody></table>';
}

function vtBadge(vt){
  if(!vt) return '';
  if(vt.found === false){
    return `<a class="vt-badge" target="_blank" rel="noopener" href="${esc(vt.permalink)}">VT: not in DB</a>`;
  }
  if(typeof vt.detected_by !== 'number' || typeof vt.total_engines !== 'number') return '';
  return `<a class="vt-badge" target="_blank" rel="noopener" href="${esc(vt.permalink)}">VT: ${esc(vt.detected_by)}/${esc(vt.total_engines)}</a>`;
}

function renderScans(rows){
  const el = document.getElementById('scan-table');
  document.getElementById('scan-count').textContent = `(${rows.length})`;
  if(!rows.length){ el.innerHTML = '<div class="empty">暂无扫描记录</div>'; return; }
  let html = '<table><thead><tr><th>时间</th><th>类型</th><th>判定</th><th>置信度</th><th>路径</th></tr></thead><tbody>';
  for(const r of rows.slice(0, 50)){
    html += `<tr>
      <td>${esc(fmtTs(r.timestamp))}</td>
      <td><span class="pill">${esc(r.file_type)}</span></td>
      <td class="${verdictClass(r.verdict)}">${esc(r.verdict)}${vtBadge(r.vt_result)}</td>
      <td>${fmtConf(r.confidence)}</td>
      <td class="mono">${esc(r.path)}</td>
    </tr>`;
  }
  el.innerHTML = html + '</tbody></table>';
}

function renderBehavior(rows){
  const el = document.getElementById('behavior-table');
  document.getElementById('behavior-count').textContent = `(${rows.length})`;
  if(!rows.length){ el.innerHTML = '<div class="empty">暂无行为告警</div>'; return; }
  let html = '<table><thead><tr><th>时间</th><th>规则</th><th>严重度</th><th>进程</th><th>父进程</th></tr></thead><tbody>';
  for(const r of rows.slice(0, 50)){
    html += `<tr>
      <td>${esc(fmtTs(r.timestamp))}</td>
      <td class="mono">${esc(r.rule_id)}</td>
      <td class="sev-${esc(r.severity)}">${esc(r.severity)}</td>
      <td class="mono">${esc(r.process_name)} <span class="muted">(pid ${esc(r.pid)})</span></td>
      <td class="mono">${esc(r.parent_name || '?')}</td>
    </tr>`;
  }
  el.innerHTML = html + '</tbody></table>';
}

function renderQuar(rows){
  const el = document.getElementById('quar-table');
  document.getElementById('quar-count').textContent = `(${rows.length})`;
  if(!rows.length){ el.innerHTML = '<div class="empty">隔离区为空</div>'; return; }
  let html = '<table><thead><tr><th>隔离文件</th><th>类型</th><th>判定</th><th>置信度</th><th>原始路径</th><th>操作</th></tr></thead><tbody>';
  for(const r of rows){
    const idEsc = esc(r.id);
    html += `<tr>
      <td class="mono">${idEsc}</td>
      <td><span class="pill">${esc(r.file_type)}</span></td>
      <td class="${verdictClass(r.verdict)}">${esc(r.verdict)}</td>
      <td>${fmtConf(r.confidence)}</td>
      <td class="mono">${esc(r.original_path)}</td>
      <td>
        <button onclick="doAction('${idEsc}','restore')">还原</button>
        <button class="danger" onclick="doAction('${idEsc}','delete')">删除</button>
      </td>
    </tr>`;
  }
  el.innerHTML = html + '</tbody></table>';
}

async function doAction(id, kind){
  if(kind === 'delete' && !confirm('确定永久删除 '+id+' ？')) return;
  const r = await fetch('/api/quarantine/'+kind, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({id})
  });
  const j = await r.json();
  if(!r.ok){ alert(j.error || 'failed'); }
  refresh();
}

async function refresh(){
  const [m, s, b, q] = await Promise.all([
    loadJSON('/api/models'),
    loadJSON('/api/scans'),
    loadJSON('/api/behavior'),
    loadJSON('/api/quarantine'),
  ]);
  if(m) renderModels(m);
  if(s) renderScans(s.entries);
  if(b) renderBehavior(b.entries);
  if(q) renderQuar(q.entries);
  document.getElementById('updated').textContent = '(更新于 ' + new Date().toLocaleTimeString() + ')';
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(_INDEX_HTML)


@app.route("/api/scans")
def api_scans():
    return jsonify({"entries": _tail_jsonl(SCAN_LOG)})


@app.route("/api/behavior")
def api_behavior():
    return jsonify({"entries": _tail_jsonl(BEHAVIOR_LOG)})


@app.route("/api/quarantine")
def api_quarantine():
    return jsonify({"entries": _list_quarantine()})


@app.route("/api/models")
def api_models():
    if not os.path.isfile(CHANGELOG):
        return jsonify({"models": []})
    try:
        with open(CHANGELOG, "r", encoding="utf-8") as f:
            cl = json.load(f)
    except Exception:
        return jsonify({"models": []})
    out = []
    for name, versions in cl.items():
        if not versions:
            continue
        # Find the last accepted version's metadata.
        current = next((v for v in reversed(versions)
                        if v["version"] == 1 or v.get("accepted", False)), versions[-1])
        out.append({
            "name": name,
            "current_version": current["version"],
            "f1": current.get("f1_after"),
            "versions_logged": len(versions),
            "last_change": versions[-1].get("change"),
        })
    return jsonify({"models": out})


@app.route("/api/quarantine/restore", methods=["POST"])
def api_restore():
    body = request.get_json(silent=True) or {}
    qid = body.get("id")
    if not qid:
        return jsonify({"error": "missing id"}), 400
    quar = _safe_quar_path(qid)
    sidecar = quar + ".json"
    dest_dir = RESTORE_DIR
    os.makedirs(dest_dir, exist_ok=True)
    # Strip the .quar suffix when writing the restored copy.
    out_name = os.path.basename(quar)
    if out_name.endswith(".quar"):
        out_name = out_name[:-len(".quar")]
    dest = os.path.join(dest_dir, out_name)
    n = 1
    base = dest
    while os.path.exists(dest):
        stem, ext = os.path.splitext(base)
        dest = f"{stem} ({n}){ext}"
        n += 1
    shutil.move(quar, dest)
    if os.path.isfile(sidecar):
        try:
            os.remove(sidecar)
        except OSError:
            pass
    return jsonify({"restored_to": dest})


@app.route("/api/quarantine/delete", methods=["POST"])
def api_delete():
    body = request.get_json(silent=True) or {}
    qid = body.get("id")
    if not qid:
        return jsonify({"error": "missing id"}), 400
    quar = _safe_quar_path(qid)
    sidecar = quar + ".json"
    try:
        os.remove(quar)
    except OSError as e:
        return jsonify({"error": str(e)}), 500
    if os.path.isfile(sidecar):
        try:
            os.remove(sidecar)
        except OSError:
            pass
    return jsonify({"deleted": qid})


# ---------- Entry ----------------------------------------------------------

def run(host: str = "127.0.0.1", port: int = 7331, debug: bool = False):
    app.run(host=host, port=port, debug=debug, use_reloader=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7331)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()
    run(args.host, args.port, args.debug)


if __name__ == "__main__":
    main()
