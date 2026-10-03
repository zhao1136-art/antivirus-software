"""
本地控制 API —— 只监听 127.0.0.1，零第三方依赖（http.server）

**自带状态页已移除**：界面统一由主产品（`backend\\frontend\\guard.html`）提供，
这里只保留主产品需要的控制 API，避免出现两套前端。

    低  low     5%
    中  medium  10%
    高  high    15%

对外接口（JSON）：
    GET  /api/status    运行状态快照：档位 + 实测占用 + 扫描统计
                        （顶层含 level/target_pct/actual_pct/budget_cores/cores/levels，
                          同时保留原有的 throttle/stats 嵌套结构，数据只有一份）
    POST /api/throttle  {"level": "low"|"medium"|"high"} -> 切换档位并返回新状态
    POST /api/level     同上，历史名，保留兼容

字段取自 `Throttle.status()` 与 `Probe.status()`，本模块不重复计算。
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["StatusServer"]

# 顶层摊平哪些档位字段（值仍来自 throttle.status()，不另造一份）
_FLAT_KEYS = ("level", "label", "target_pct", "actual_pct",
              "cores", "budget_cores", "levels")


def _flatten(payload: dict) -> dict:
    """把列表页用的嵌套结构摊平一层：throttle.* 同时出现在顶层。

    只是视图层的关键字搬运，档位/占用的计算仍在 Throttle 里。
    """
    data = dict(payload or {})
    th = data.get("throttle")
    if isinstance(th, dict):
        for k in _FLAT_KEYS:
            if k in th and k not in data:
                data[k] = th[k]
    return data


class _Handler(BaseHTTPRequestHandler):
    server_version = "rtguard/1.0"

    def log_message(self, fmt, *args):   # 静默，避免刷日志
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

    def _send_json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _snapshot(self) -> dict:
        try:
            data = self.server.provider()
        except Exception as exc:
            data = {"error": str(exc)}
        if not isinstance(data, dict):
            data = {"error": "状态provider返回了非字典: %r" % (data,)}
        return _flatten(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/status":
            self._send_json(200, self._snapshot())
        elif path in ("/", "/index.html"):
            # 页面已移到主产品；这里给个机器可读的路标，不再返回 HTML
            self._send_json(200, {
                "service": "rtguard",
                "ui": "removed",
                "note": "状态页已并入主产品 guard.html，此处只提供控制 API",
                "api": ["GET /api/status", "POST /api/throttle"],
            })
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/api/throttle", "/api/level"):
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(n) or b"{}")
            level = str(payload.get("level", "")).strip().lower()
            ok = bool(self.server.on_set_level(level))
            body = self._snapshot()
            body["ok"] = ok
            body["requested"] = level
            if not ok:
                body["error"] = "非法档位: %s（只支持 low/medium/high）" % level
            self._send_json(200 if ok else 400, body)
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})


class StatusServer:
    """本地控制 API。只绑定 127.0.0.1，不对外暴露。"""

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
