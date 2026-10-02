"""
本地状态页 —— 只监听 127.0.0.1，零第三方依赖（http.server）

页面就一件事最要紧：**限速档位**。三个按钮 低 5% / 中 10% / 高 15%，
切换实时防护允许占用的系统 CPU 上限。其余是状态展示：匹配后端、规则数、
扫描计数、实际占用。

对外接口：
    GET  /              状态页
    GET  /api/status    JSON 快照
    POST /api/level     {"level": "low"|"medium"|"high"}
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["StatusServer"]

_PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>御天实时防护</title>
<style>
:root{--bg:#12151a;--card:#1b2027;--fg:#e6e9ee;--dim:#8b95a3;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--acc:#2f81f7}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 "Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:28px 20px}
h1{font-size:19px;margin:0 0 4px}
.sub{color:var(--dim);font-size:12px;margin-bottom:22px}
.card{background:var(--card);border:1px solid #232a33;border-radius:10px;padding:18px;margin-bottom:16px}
.card h2{font-size:13px;color:var(--dim);margin:0 0 14px;font-weight:600;letter-spacing:.4px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.kv .k{color:var(--dim);font-size:12px}
.kv .v{font-size:17px;font-weight:600;margin-top:2px}
.levels{display:flex;gap:10px}
.lv{flex:1;background:#222932;border:1px solid #2c343f;border-radius:9px;padding:14px 10px;text-align:center;cursor:pointer;transition:.15s;color:var(--fg);font:inherit}
.lv:hover{border-color:var(--acc)}
.lv.on{background:#12325c;border-color:var(--acc)}
.lv .n{font-size:16px;font-weight:600}
.lv .p{color:var(--dim);font-size:12px;margin-top:3px}
.lv.on .p{color:#9dc4ff}
.bar{height:8px;background:#222932;border-radius:5px;overflow:hidden;margin-top:10px}
.bar i{display:block;height:100%;background:var(--ok);width:0;transition:width .4s}
.bar.over i{background:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #232a33}
th{color:var(--dim);font-weight:600;font-size:12px}
.mono{font-family:Consolas,monospace;font-size:12px}
.tag{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px}
.t-clean{background:#12351c;color:var(--ok)}
.t-suspicious{background:#3a2f10;color:var(--warn)}
.t-malicious{background:#3d1518;color:var(--bad)}
</style></head><body><div class="wrap">
<h1>御天实时防护</h1>
<div class="sub" id="sub">正在连接…</div>

<div class="card">
  <h2>限速档位 · 占用系统 CPU 上限</h2>
  <div class="levels" id="levels"></div>
  <div class="bar" id="bar"><i id="barfill"></i></div>
  <div class="sub" style="margin:10px 0 0" id="loadtxt"></div>
</div>

<div class="card">
  <h2>运行状态</h2>
  <div class="grid" id="stats"></div>
</div>

<div class="card">
  <h2>最近告警</h2>
  <table><thead><tr><th>判定</th><th>文件</th><th>规则</th></tr></thead>
  <tbody id="alerts"><tr><td colspan="3" style="color:#8b95a3">暂无</td></tr></tbody></table>
</div>
</div>
<script>
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function render(d){
  document.getElementById('sub').textContent =
    '后端 ' + d.backend + ' · 运行 ' + d.uptime_h + ' 小时';
  var lv = document.getElementById('levels'); lv.innerHTML = '';
  Object.keys(d.levels).forEach(function(k){
    var v = d.levels[k], el = document.createElement('div');
    el.className = 'lv' + (k === d.throttle.level ? ' on' : '');
    el.innerHTML = '<div class="n"></div><div class="p"></div>';
    el.querySelector('.n').textContent = v.label;
    el.querySelector('.p').textContent = '上限 ' + v.pct + '%';
    el.onclick = function(){ setLevel(k); };
    lv.appendChild(el);
  });
  var pct = d.throttle.actual_pct, target = d.throttle.target_pct;
  document.getElementById('barfill').style.width = Math.min(100, pct / Math.max(target,1) * 100) + '%';
  document.getElementById('bar').className = 'bar' + (pct > target * 1.5 ? ' over' : '');
  document.getElementById('loadtxt').textContent =
    '实际 ' + pct + '% / 目标 ' + target + '%  ·  允许 ' + d.throttle.budget_cores +
    ' 核（' + d.throttle.cores + ' 核机器）';
  var s = d.stats, g = document.getElementById('stats'); g.innerHTML = '';
  [['规则', s.rules], ['已扫描', s.scanned], ['跳过', s.skipped],
   ['可疑', s.suspicious], ['恶意', s.malicious], ['隔离区', s.quarantine],
   ['扫描字节', s.bytes_h], ['缓存命中', s.cache_hits]].forEach(function(p){
    var el = document.createElement('div'); el.className = 'kv';
    el.innerHTML = '<div class="k"></div><div class="v"></div>';
    el.querySelector('.k').textContent = p[0];
    el.querySelector('.v').textContent = p[1];
    g.appendChild(el);
  });
  var tb = document.getElementById('alerts'); tb.innerHTML = '';
  if(!d.alerts || !d.alerts.length){
    tb.innerHTML = '<tr><td colspan="3" style="color:#8b95a3">暂无</td></tr>';
  } else {
    d.alerts.forEach(function(a){
      var tr = document.createElement('tr');
      tr.innerHTML = '<td><span class="tag t-'+a.verdict+'">'+a.verdict+'</span></td>'+
                     '<td class="mono"></td><td></td>';
      tr.children[1].textContent = a.path;
      tr.children[2].textContent = (a.rules||[]).join(', ');
      tb.appendChild(tr);
    });
  }
}
function setLevel(k){
  fetch('/api/level',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({level:k})}).then(function(){ tick(); });
}
function tick(){
  fetch('/api/status').then(function(r){return r.json()}).then(render)
    .catch(function(e){ document.getElementById('sub').textContent = '连接失败: ' + e; });
}
tick(); setInterval(tick, 2000);
</script></body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "rtguard/1.0"

    def log_message(self, fmt, *args):   # 静默，避免刷控制台
        pass

    def _send(self, code, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/status":
            try:
                data = self.server.provider()
            except Exception as exc:
                data = {"error": str(exc)}
            self._send(200, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path in ("/", "/index.html"):
            self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/level":
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(n) or b"{}")
            level = str(payload.get("level", "")).lower()
            ok = bool(self.server.on_set_level(level))
            body = json.dumps({"ok": ok, "level": level}, ensure_ascii=False)
            self._send(200 if ok else 400, body.encode("utf-8"),
                       "application/json; charset=utf-8")
        except Exception as exc:
            self._send(400, json.dumps({"ok": False, "error": str(exc)}).encode("utf-8"),
                       "application/json; charset=utf-8")


class StatusServer:
    """本地状态页。只绑定 127.0.0.1，不对外暴露。"""

    def __init__(self, provider, on_set_level, host="127.0.0.1", port=8022):
        self.provider = provider
        self.on_set_level = on_set_level
        self.host = host
        self.port = int(port)
        self.httpd = None
        self._thread = None

    @property
    def url(self) -> str:
        return "http://%s:%d/" % (self.host, self.port)

    def start(self, port_fallbacks=4) -> bool:
        """端口被占用时顺延尝试若干次。失败返回 False，不抛异常。"""
        for offset in range(max(1, port_fallbacks)):
            port = self.port + offset
            try:
                httpd = ThreadingHTTPServer((self.host, port), _Handler)
            except OSError:
                continue
            httpd.daemon_threads = True
            httpd.provider = self.provider
            httpd.on_set_level = self.on_set_level
            self.httpd = httpd
            self.port = port
            self._thread = threading.Thread(target=httpd.serve_forever,
                                            kwargs={"poll_interval": 0.3},
                                            daemon=True, name="rtguard-ui")
            self._thread.start()
            return True
        return False

    def stop(self, timeout=2.0):
        if self.httpd is not None:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
