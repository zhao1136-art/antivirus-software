"""后端 HTTP 客户端与异步桥 —— 只用标准库。

后端契约来源：``backend/app.py``（uvicorn 监听 ``127.0.0.1:8899``）。
本模块涉及的接口字段都按 app.py 里的真实返回结构写，不猜测。

两个设计约束
------------
1. **后端可能没在跑。** 所有调用都收敛成 ``ApiResult``，网络错误不抛给调用方，
   由页面决定显示"后端未连接"还是别的。独立 UI 不能因为后端缺席就崩。
2. **Tk 不是线程安全的。** 任何控件操作都必须在主线程做。网络请求一律走
   :func:`run_async`，结果通过 ``widget.after(0, ...)`` 回到主线程。
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, NamedTuple

DEFAULT_BASE = "http://127.0.0.1:8899"
# 统一超时，取短值。
# 后端是本地进程：没在跑时是 connection refused（立刻失败），所以这个值只决定
# "后端活着但慢"时肯等多久。保持短，界面才不会显得卡死。
#
# 关于冷启动（重要，别为此把超时拉长）：
#   统计子系统是惰性初始化的，/api/v1/stats/overview 冷态首调实测 25s 起，
#   负载高时超过 40s。后端又是**单事件循环**（uvicorn），这一个冷调用会把
#   排队在后面的请求一起堵住。
#   曾被改成 35s、又试过给该接口单独 40s，两种都不划算：
#     · 拉长全局 → "后端忙"时界面白等 35 秒才认输，观感更差
#     · 单独放宽 → 40s 也不保证够，反而白占一个工作线程
#   正确做法是**短超时 + 依赖页面轮询自愈**：概览页每 5 秒刷新一次，
#   头几次会失败（显示空值），等后端预热完成后下一次轮询就正常了。
#   实测：冷态首轮 48 个接口里只有 stats_overview 失败，同一后端再跑一轮
#   48/48 全过 —— 自愈是成立的。
DEFAULT_TIMEOUT = 6.0


class ApiResult(NamedTuple):
    """统一返回：``ok`` 为 False 时 ``error`` 一定有值，``data`` 为 None。"""

    ok: bool
    data: Any = None
    error: str = ""
    status: int = 0


class ApiClient:
    """极简 HTTP 客户端。线程安全（内部 CookieJar 自带锁）。

    鉴权说明（2026-10-31 起**没有令牌**）
    ------------------------------------
    后端 `_LocalOriginGuard` 只拦「带 Origin 且不是本机」的请求：
      · Tk 客户端发的是不带 Origin 的原生 HTTP 请求 → 直连放行
      · 同源 HTML 页面（服务自己托管）→ 放行
      · 任意外部网页的跨源请求 → 403
    因此这里**不需要任何令牌文件、Cookie 或请求头**。
    之前那套「令牌写文件 + x-yutian-token 头」已整体移除：它在冻结态曾因
    目录解析问题导致令牌写不出来、所有 /api/* 直接 401，扫描不可用。
    """

    def __init__(self, base: str = DEFAULT_BASE, timeout: float = DEFAULT_TIMEOUT):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar))

    # ── 内部 ──

    def _send(self, req: urllib.request.Request, timeout: float):
        """走带 Cookie 的 opener（Cookie 仅用于可能存在的其他会话状态）。"""
        return self._opener.open(req, timeout=timeout)

    def _request(self, method: str, path: str, payload: dict | None = None,
                 _retry: bool = True, timeout: float | None = None) -> ApiResult:
        effective_timeout = self.timeout if timeout is None else float(timeout)
        url = self.base + path
        body = None
        headers = {"Accept": "application/json"}

        if payload is not None:
            try:
                body = json.dumps(payload).encode("utf-8")
            except (TypeError, ValueError) as exc:
                return ApiResult(False, None, f"请求体无法序列化: {exc}")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self._send(req, effective_timeout) as resp:
                raw = resp.read()
                status = getattr(resp, "status", 200)
        except urllib.error.HTTPError as exc:
            # 4xx/5xx 也算"后端在跑"，把服务端的 error 字段透出来给用户看
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:400]
            except Exception:
                pass
            return ApiResult(False, None, detail or f"HTTP {exc.code}", exc.code)
        except urllib.error.URLError as exc:
            return ApiResult(False, None, f"无法连接后端 ({exc.reason})")
        except (TimeoutError, OSError) as exc:
            return ApiResult(False, None, f"连接失败: {exc}")

        if not raw:
            return ApiResult(True, None, "", status)
        try:
            return ApiResult(True, json.loads(raw.decode("utf-8")), "", status)
        except (UnicodeDecodeError, json.JSONDecodeError):
            # 不是 JSON（例如 FileResponse 返回了 HTML）——原样吐回，不静默丢数据
            return ApiResult(True, raw.decode("utf-8", "replace"), "", status)

    # ── 公开 ──

    def get(self, path: str, timeout: float | None = None) -> ApiResult:
        return self._request("GET", path, timeout=timeout)

    def post(self, path: str, payload: dict | None = None,
             timeout: float | None = None) -> ApiResult:
        return self._request("POST", path, payload if payload is not None else {},
                             timeout=timeout)

    def delete(self, path: str, timeout: float | None = None) -> ApiResult:
        return self._request("DELETE", path, timeout=timeout)

    # ── 领域方法（字段名严格对齐 app.py）──

    def stats_overview(self) -> ApiResult:
        """``/api/v1/stats/overview`` → total_scanned / today_blocked / guard_days 等

        冷启动首调可能超时（统计子系统惰性初始化，实测 25s 起）。
        这是**预期行为**：页面每 5 秒轮询一次，后端预热完成后自愈，
        详见 DEFAULT_TIMEOUT 处的说明。
        """
        return self.get("/api/v1/stats/overview")

    def stats_activity(self) -> ApiResult:
        """``/api/v1/stats/activity`` → ``{"threats": [...], "scans": [...]}``

        与 stats_overview 共享统计子系统，冷启动同样可能首次超时，靠轮询自愈。
        """
        return self.get("/api/v1/stats/activity")

    def protection_status(self) -> ApiResult:
        """``/api/v1/protection/status`` → ``{"modules": {...}, "realtime_enabled": bool}``"""
        return self.get("/api/v1/protection/status")

    def protection_toggle(self, module: str, enabled: bool) -> ApiResult:
        return self.post("/api/v1/protection/toggle",
                         {"module": module, "enabled": bool(enabled)})

    def scan_start(self, scan_type: str, paths: list[str] | None = None) -> ApiResult:
        """scan_type ∈ {quick, full, custom}；custom 需带 paths。"""
        if scan_type == "quick":
            return self.post("/api/v1/scan/quick")
        if scan_type == "full":
            return self.post("/api/v1/scan/full")
        return self.post("/api/v1/scan/custom", {"paths": list(paths or [])})

    def scan_status(self, task_id: str) -> ApiResult:
        """→ task.to_dict(): status / progress / current_file / result / error"""
        return self.get(f"/api/v1/scan/{task_id}/status")

    def scan_cancel(self, task_id: str) -> ApiResult:
        return self.post(f"/api/v1/scan/{task_id}/cancel")

    def quarantine_list(self) -> ApiResult:
        """→ ``{"total": n, "items": [...]}``"""
        return self.get("/api/v1/quarantine")

    def quarantine_restore(self, qid: str) -> ApiResult:
        return self.post("/api/v1/quarantine/restore", {"id": qid})

    def quarantine_delete(self, qid: str) -> ApiResult:
        return self.delete(f"/api/v1/quarantine/{qid}")

    def quarantine_restore_all(self) -> ApiResult:
        return self.post("/api/v1/quarantine/restore-all")

    def quarantine_delete_all(self) -> ApiResult:
        return self.delete("/api/v1/quarantine")

    def quarantine_report_fp(self, qid: str, note: str = "") -> ApiResult:
        """上报「这是用户认为的误报」。

        后端会自己补判定上下文 —— 目录类别、是否系统路径、扩展名、大小、
        原始威胁名/等级。这些**只有隔离那一刻才知道**，事后问用户是问不出来的。
        只传 id 和可选备注，不传文件内容。
        """
        return self.post("/api/v1/quarantine/report-false-positive",
                         {"id": qid, "note": note})

    def threats_pending(self) -> ApiResult:
        """→ ``{"pending": [...], "timeout": 15.0, "stats": {...}}``"""
        return self.get("/api/v1/threats/pending")

    def threat_decide(self, pending_id: str, action: str) -> ApiResult:
        """action ∈ {quarantine, ignore}"""
        return self.post(f"/api/v1/threats/{pending_id}/decide", {"action": action})

    def version(self) -> ApiResult:
        return self.get("/api/v1/version")

    def health(self) -> ApiResult:
        """``/api/health`` —— 存活探测，附带引擎/签名/内存/磁盘信息"""
        return self.get("/api/health")

    def signatures_info(self) -> ApiResult:
        """→ ``{"total_signatures": n, "by_level": {...}, "version": str}``"""
        return self.get("/api/v1/signatures/info")

    def guard_days(self) -> ApiResult:
        return self.get("/api/v1/guard-days")

    def logs_clear(self) -> ApiResult:
        return self.post("/api/v1/logs/clear")

    # ── 通用可取消异步任务（/api/v1/jobs）──
    #
    # 长耗时任务走这条通道：POST 创建返回 task_id，再轮询状态，可取消。
    # 状态字段（app.py 的 _AsyncJob.to_dict）：
    #   task_id / kind / status / progress / current / result / error / cancelled
    # 注意: 这里**不**提供 rootkit-scan。ISSUES.md 2.1 记录了
    #   anti_rootkit.scan() 会以 0xC0000005 直接杀死解释器（try/except 抓不到），
    #   放个按钮上去等于一点就把整个后端打崩。

    def job_create(self, kind: str, params: dict | None = None) -> ApiResult:
        return self.post("/api/v1/jobs", {"kind": kind, "params": params or {}})

    def job_status(self, task_id: str) -> ApiResult:
        return self.get(f"/api/v1/jobs/{task_id}/status")

    def job_cancel(self, task_id: str) -> ApiResult:
        return self.post(f"/api/v1/jobs/{task_id}/cancel")

    # ── 安全工具：网络急救 ──

    def network_check(self) -> ApiResult:
        """→ ``{dns_ok, ping_ok, internet_ok, hosts_ok, hosts_entries, lsp_ok, details[]}``"""
        return self.get("/api/v1/network/check")

    def network_repair(self, kind: str = "all") -> ApiResult:
        """``kind`` ∈ {all, hosts, dns, lsp}"""
        if kind == "all":
            return self.post("/api/v1/network/repair-all")
        return self.post(f"/api/v1/network/repair-{kind}")

    # ── 安全工具：网址防护 ──

    def urlguard_status(self) -> ApiResult:
        return self.get("/api/v1/urlguard/status")

    def urlguard_check(self, url: str) -> ApiResult:
        """→ ``{url, host, level: safe|suspicious|malicious, reason, families, in_blocked}``"""
        return self.post("/api/v1/urlguard/check", {"url": url})

    def urlguard_toggle(self, enabled: bool) -> ApiResult:
        # 这个端点收 ToggleRequest，module 是必填字段（缺了会 422）
        return self.post("/api/v1/urlguard/toggle",
                         {"module": "url_guard", "enabled": bool(enabled)})

    # ── 安全工具：漏洞修复 ──

    def vulnfix_status(self) -> ApiResult:
        """→ ``{scan_time, installed_count, missing_count, all_patched, missing[], ...}``"""
        return self.get("/api/v1/vulnfix/status")

    def vulnfix_open_update(self) -> ApiResult:
        """唤起系统更新设置页（不擅自下载安装补丁）"""
        return self.post("/api/v1/vulnfix/open-update")

    # ── 安全工具：U 盘与外设 ──

    def usb_guard_status(self) -> ApiResult:
        """→ ``{removable_drives[], immunized_drives[], autorun_enabled, usb_storage_enabled}``"""
        return self.get("/api/v1/usb-guard/status")

    def usb_guard_immunize(self, drive: str | None = None) -> ApiResult:
        """drive 为空表示对所有可移动盘执行免疫"""
        return self.post("/api/v1/usb-guard/immunize",
                         {"drive": drive} if drive else {})

    def usb_guard_autorun(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/usb-guard/autorun", {"enabled": bool(enabled)})

    def usb_guard_usb_storage(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/usb-guard/usb-storage", {"enabled": bool(enabled)})

    # ── 安全工具：邮件/文本钓鱼检测 ──

    def mail_guard_status(self) -> ApiResult:
        """→ ``{scanned, flagged, history[]}``"""
        return self.get("/api/v1/mail-guard/status")

    def mail_guard_scan_text(self, text: str) -> ApiResult:
        """→ ``{risk: safe|suspicious|malicious, flagged, url_count, alerts[], urls[]}``"""
        return self.post("/api/v1/mail-guard/scan-text", {"text": text})

    # ── 安全工具：四个"开关型"防护 ──
    # 这四个 toggle 都收 ToggleRequest，module 与 _feature_toggles 的键一致。

    def adblock_status(self) -> ApiResult:
        """→ ``{enabled, running, blocked_total, strict_mode}``"""
        return self.get("/api/v1/adblock/status")

    def adblock_toggle(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/adblock/toggle",
                         {"module": "adblock", "enabled": bool(enabled)})

    def registry_guard_status(self) -> ApiResult:
        """→ ``{enabled, running, blocked_total, auto_restore, monitored_keys_count}``"""
        return self.get("/api/v1/registry-guard/status")

    def registry_guard_toggle(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/registry-guard/toggle",
                         {"module": "registry_guard", "enabled": bool(enabled)})

    def behavior_block_status(self) -> ApiResult:
        """→ ``{enabled, running, blocked_total, monitored_commands, monitored_processes}``"""
        return self.get("/api/v1/behavior-block/status")

    def behavior_block_toggle(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/behavior-block/toggle",
                         {"module": "behavior_block", "enabled": bool(enabled)})

    def process_guard_status(self) -> ApiResult:
        """→ ``{enabled, running, blocked_total, blacklist_size, whitelist_size}``"""
        return self.get("/api/v1/process-guard/status")

    def process_guard_toggle(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/process-guard/toggle",
                         {"module": "process_guard_tool", "enabled": bool(enabled)})

    # ── 安全工具：下载防护 ──

    def download_guard_status(self) -> ApiResult:
        """→ ``{enabled, running, scan_total, threat_total, watch_dirs_count}``"""
        return self.get("/api/v1/download-guard/status")

    def download_guard_toggle(self, enabled: bool) -> ApiResult:
        # 收 ToggleRequest，module 必填
        return self.post("/api/v1/download-guard/toggle",
                         {"module": "download_guard", "enabled": bool(enabled)})

    def download_guard_stats(self) -> ApiResult:
        """→ ``{enabled, scan_count, threat_count, watch_dirs[], recent_threats[]}``"""
        return self.get("/api/v1/download-guard/stats")

    def download_guard_dirs(self) -> ApiResult:
        """→ ``{"dirs": [...]}``"""
        return self.get("/api/v1/download-guard/dirs")

    def download_guard_dir_add(self, path: str) -> ApiResult:
        return self.post("/api/v1/download-guard/dir-add", {"path": path})

    def download_guard_dir_remove(self, path: str) -> ApiResult:
        return self.post("/api/v1/download-guard/dir-remove", {"path": path})

    # ── 安全工具：网址防护名单管理 ──

    def urlguard_block(self, url: str) -> ApiResult:
        """→ ``{success, blocked[]}``"""
        return self.post("/api/v1/urlguard/block", {"url": url})

    def urlguard_unblock(self, url: str) -> ApiResult:
        return self.post("/api/v1/urlguard/unblock", {"url": url})

    def urlguard_blocked(self) -> ApiResult:
        """→ ``{"blocked": [...]}``"""
        return self.get("/api/v1/urlguard/blocked")

    def urlguard_hosts_sync(self, enabled: bool) -> ApiResult:
        """把阻断名单应用/清除到 hosts"""
        return self.post("/api/v1/urlguard/hosts-sync", {"enabled": bool(enabled)})

    def urlguard_whitelist(self) -> ApiResult:
        """→ ``{"whitelist": [...]}``"""
        return self.get("/api/v1/urlguard/whitelist")

    def urlguard_whitelist_add(self, url: str) -> ApiResult:
        return self.post("/api/v1/urlguard/whitelist-add", {"url": url})

    def urlguard_whitelist_remove(self, url: str) -> ApiResult:
        return self.post("/api/v1/urlguard/whitelist-remove", {"url": url})

    # ── 安全工具：沙箱分析（走 jobs，可取消）──

    def sandbox_analyze_job(self, file_path: str, timeout: int = 30) -> ApiResult:
        """提交沙箱分析任务；结果经 job_status 取 ``result``（analyze_file 报告）"""
        return self.job_create("sandbox-analyze",
                               {"file_path": file_path, "timeout": int(timeout)})

    # ── 安全工具：云样本多引擎比对（multipart 上传）──

    def cloud_sample_submit(self, file_path: str) -> ApiResult:
        """上传本地文件做哈希研判。

        → ``{sha256, md5, size_bytes, filename, known, lookup}``
        这是**唯一**需要 multipart 的接口，见 :meth:`_post_multipart`。
        """
        return self._post_multipart("/api/v1/cloud/sample/submit", file_path)

    def _post_multipart(self, path: str, file_path: str,
                        field: str = "file") -> ApiResult:
        """极简 multipart/form-data 上传（标准库手搓 body）。

        只支持单文件字段 —— 后端这两个上传接口（云样本 / 沙箱上传）都只收一个
        ``file``。刻意不引入 requests 之类的依赖。
        """
        import mimetypes
        import os
        import uuid

        try:
            with open(file_path, "rb") as fh:
                content = fh.read()
        except OSError as exc:
            return ApiResult(False, None, f"读取文件失败: {exc}")

        filename = os.path.basename(file_path) or "sample.bin"
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        boundary = "----andunui" + uuid.uuid4().hex

        head = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n"
        ).encode("utf-8")
        tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
        body = head + content + tail

        headers = {
            "Accept": "application/json",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        }
        req = urllib.request.Request(self.base + path, data=body,
                                     headers=headers, method="POST")
        try:
            # 上传可能较大，超时放宽；同样要走带 Cookie 的 opener
            with self._send(req, max(self.timeout, 60.0)) as resp:
                raw = resp.read()
                status = getattr(resp, "status", 200)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:400]
            except Exception:
                pass
            return ApiResult(False, None, detail or f"HTTP {exc.code}", exc.code)
        except urllib.error.URLError as exc:
            return ApiResult(False, None, f"无法连接后端 ({exc.reason})")
        except (TimeoutError, OSError) as exc:
            return ApiResult(False, None, f"上传失败: {exc}")

        try:
            return ApiResult(True, json.loads(raw.decode("utf-8")), "", status)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ApiResult(True, raw.decode("utf-8", "replace"), "", status)

    # ── 垃圾清理 ──

    def clean_scan(self) -> ApiResult:
        """→ ``{task_id, status}``"""
        return self.post("/api/v1/clean/scan")

    def clean_status(self, task_id: str) -> ApiResult:
        """→ ``{task_id, status, progress, current_item, result, cancelled, error}``

        ``result`` 形如 ``{categories: [{id,name,desc,file_count,total_bytes,
        size_text,items,skipped}], total_bytes, total_files}``
        """
        return self.get(f"/api/v1/clean/{task_id}/status")

    def clean_cancel(self, task_id: str) -> ApiResult:
        return self.post(f"/api/v1/clean/{task_id}/cancel")

    def clean_execute(self, category_ids: list[str]) -> ApiResult:
        """→ ``{success, cancelled, freed_bytes, freed_text, cleaned_files,
        categories[], failed[]}``"""
        return self.post("/api/v1/clean/execute",
                         {"category_ids": list(category_ids)})

    def clean_history(self, limit: int = 20) -> ApiResult:
        """→ ``{"records": [...]}``"""
        return self.get(f"/api/v1/clean/history?limit={int(limit)}")

    # ── 电脑优化 ──

    def optimize_overview(self) -> ApiResult:
        """→ ``{score, checks[{id,name,status,detail}], disk{}, memory{}, temp{},
        startup_count, pending_reboot}``"""
        return self.get("/api/v1/optimize/overview")

    def optimize_startup(self) -> ApiResult:
        """→ ``{"items": [{item_id,type,name,source,status,detail}]}``"""
        return self.get("/api/v1/optimize/startup")

    def optimize_startup_toggle(self, item_id: str, action: str) -> ApiResult:
        """``action`` ∈ {disable, enable}"""
        return self.post("/api/v1/optimize/startup/toggle",
                         {"item_id": item_id, "action": action})

    def optimize_services(self) -> ApiResult:
        """→ ``{readonly[], manageable[], readonly_count, manageable_count}``

        条目形如 ``{name, display, state, start_type, image_path}``。
        **只有 manageable 里的第三方服务可改**，系统服务是只读的。
        """
        return self.get("/api/v1/optimize/services")

    def optimize_service_toggle(self, name: str, action: str) -> ApiResult:
        """``action`` ∈ {auto, manual, disabled}"""
        return self.post("/api/v1/optimize/services/toggle",
                         {"name": name, "action": action})

    def optimize_memory(self) -> ApiResult:
        """→ ``{success, cancelled, released_bytes, released_text, processed}``"""
        return self.post("/api/v1/optimize/memory")

    def optimize_one_click(self) -> ApiResult:
        """→ ``{success, clean{}, memory{}, recommendations[]}``"""
        return self.post("/api/v1/optimize/one-click")

    # ── 病毒记忆（历史记录）──

    def history_viruses(self, limit: int = 100, keyword: str = "",
                        virus_type: str = "", engine: str = "") -> ApiResult:
        """→ 记录列表 ``[{virus_type, file_path, scan_time, sha256, md5,
        signature, threat_level, engine, task_id}]``"""
        from urllib.parse import quote
        query = [f"limit={int(limit)}"]
        for key, value in (("keyword", keyword), ("virus_type", virus_type),
                           ("engine", engine)):
            if value:
                query.append(f"{key}={quote(str(value))}")
        return self.get("/api/v1/history/viruses?" + "&".join(query))

    def history_virus_stats(self) -> ApiResult:
        """→ ``{type_count{}, engine_stats{}, total_records, unique_types[]}``"""
        return self.get("/api/v1/history/virus-stats")

    def history_virus_types(self) -> ApiResult:
        """→ ``{"types": [...]}``"""
        return self.get("/api/v1/history/virus-types")

    def history_virus_family(self, limit: int = 20) -> ApiResult:
        """→ ``{"families": [{family, count, ratio}]}``"""
        return self.get(f"/api/v1/history/virus-family?limit={int(limit)}")

    def history_clear(self) -> ApiResult:
        """→ ``{"success": bool}``"""
        return self.post("/api/v1/history/clear")

    # ── 引擎页：ETW 事中检测 ──

    def etw_status(self) -> ApiResult:
        """→ ``{running, ...}``（native_guard.dll 不可用时 running=False + error）"""
        return self.get("/api/v1/etw/status")

    def etw_start(self) -> ApiResult:
        return self.post("/api/v1/etw/start")

    def etw_stop(self) -> ApiResult:
        return self.post("/api/v1/etw/stop")

    def etw_events(self) -> ApiResult:
        """→ ``{events: [...], total}``（**获取后后端会清空**，是消费式的）"""
        return self.get("/api/v1/etw/events")

    # ── 引擎页：AMSI Provider ──
    #
    # ⚠ amsi_manager 的文档说明了为什么这里必须谨慎：
    #   只写 HKLM\...\AMSI\Providers 而不写 COM CLSID，会让**全系统 AMSI 失效**
    #   （AmsiInitialize 返回 0x80070002）。注销时也绝不能删 Providers 父键，
    #   否则会连带清掉别的厂商注册。所以这一组只暴露状态 + 显式确认后的注册/注销。

    def amsi_status(self) -> ApiResult:
        return self.get("/api/v1/amsi/status")

    def amsi_register(self) -> ApiResult:
        return self.post("/api/v1/amsi/register")

    def amsi_unregister(self) -> ApiResult:
        return self.post("/api/v1/amsi/unregister")

    # ── 引擎页：辅助功能开关总览 ──

    def features_status(self) -> ApiResult:
        """→ ``{auto_start{}, shell_menu{}, game_mode{}, usb_scan{}, tray_icon{},
        etw_guard{}, amsi_provider{}}``"""
        return self.get("/api/v1/features/status")

    # ── 引擎页：引擎清单 ──

    def cloud_engines(self) -> ApiResult:
        """→ ``{engine_order[], engines: {avic{}, threatbook{}, otx{}}, last_error}``"""
        return self.get("/api/v1/cloud/engines")

    def deep_engines(self) -> ApiResult:
        """洞渊引擎（capa / ClamAV / YARA）可用性，字段随 deep_analyzer 实现"""
        return self.get("/api/v1/deep/engines")

    def scan_perf_stats(self) -> ApiResult:
        """扫描引擎性能统计 + YARA 索引 + 实时队列水位"""
        return self.get("/api/v1/scan/perf-stats")

    # ── 自定义规则（/api/v1/rules/*）──
    #
    # 规则类型：RULE_TYPES = {file, process, registry, network, handle}
    # 动作：    ACTIONS    = {allow, block, ask}
    # 规则字段：{id, type, action, pattern, description, enabled, created_at}

    def rules_list(self, rule_type: str | None = None) -> ApiResult:
        """→ ``{"rules": [...]}``"""
        if rule_type:
            from urllib.parse import quote
            return self.get(f"/api/v1/rules/list?rule_type={quote(str(rule_type))}")
        return self.get("/api/v1/rules/list")

    def rules_add(self, rule_type: str, action: str, pattern: str,
                  description: str = "") -> ApiResult:
        """→ ``{ok, rule}``（rule 是新建的 id；参数非法时后端返回 None）"""
        return self.post("/api/v1/rules/add", {
            "rule_type": rule_type, "action": action,
            "pattern": pattern, "description": description,
        })

    def rules_remove(self, rule_id: int) -> ApiResult:
        return self.post("/api/v1/rules/remove", {"rule_id": int(rule_id)})

    def rules_toggle(self, rule_id: int, enabled: bool) -> ApiResult:
        return self.post("/api/v1/rules/toggle",
                         {"rule_id": int(rule_id), "enabled": bool(enabled)})

    def rules_templates(self) -> ApiResult:
        """→ ``{"templates": [...]}``"""
        return self.get("/api/v1/rules/templates")

    def rules_export(self) -> ApiResult:
        """→ ``{"rules": [...]}``"""
        return self.get("/api/v1/rules/export")

    def rules_import(self, rules: list) -> ApiResult:
        return self.post("/api/v1/rules/import", {"rules": list(rules)})

    def rules_stats(self) -> ApiResult:
        """→ ``{total_rules, rules}``"""
        return self.get("/api/v1/rules/stats")

    # ── 数据恢复（/api/v1/recovery/*）──

    def recovery_status(self) -> ApiResult:
        """→ ``{running, watch_dirs[], files_tracked, total_versions, stats{}}``"""
        return self.get("/api/v1/recovery/status")

    def recovery_stats(self) -> ApiResult:
        """→ ``{watched_directories, watch_dirs[], files_tracked, total_versions,
        total_storage_bytes, total_storage_mb, running, ...}``"""
        return self.get("/api/v1/recovery/stats")

    def recovery_files(self) -> ApiResult:
        """→ ``{"files": [{name, path}]}``"""
        return self.get("/api/v1/recovery/files")

    def recovery_versions(self, file_path: str) -> ApiResult:
        """→ ``{"versions": [{version_id, timestamp, hash, size}]}``"""
        from urllib.parse import quote
        return self.get("/api/v1/recovery/versions?file_path="
                        + quote(str(file_path)))

    def recovery_restore(self, file_path: str, version_id: str) -> ApiResult:
        return self.post("/api/v1/recovery/restore",
                         {"file_path": file_path, "version_id": version_id})

    def recovery_restore_job(self, file_path: str, version_id: str) -> ApiResult:
        """版本还原走 jobs（可取消 + 有进度）。

        为什么不用 ``/api/v1/recovery/restore``：那是同步接口，大文件复制会超过
        本 UI 的 6 秒超时 —— 界面报"失败"但服务端其实还在写，属于假失败。
        走 jobs 拿 task_id 轮询，行为才和实际一致。
        """
        return self.job_create("recovery-restore",
                               {"file_path": file_path, "version_id": version_id})

    def recovery_delete_version(self, file_path: str, version_id: str) -> ApiResult:
        return self.post("/api/v1/recovery/delete-version",
                         {"file_path": file_path, "version_id": version_id})

    def recovery_start(self, directories: list | None = None) -> ApiResult:
        return self.post("/api/v1/recovery/start",
                         {"directories": list(directories or [])})

    def recovery_stop(self) -> ApiResult:
        return self.post("/api/v1/recovery/stop")

    def recovery_settings(self) -> ApiResult:
        """→ ``{watch_dirs[], retain_days, storage_limit, ...}``"""
        return self.get("/api/v1/recovery/settings")

    def recovery_save_settings(self, retain_days: int = 0,
                               storage_limit: int = 0) -> ApiResult:
        return self.post("/api/v1/recovery/settings",
                         {"retain_days": int(retain_days),
                          "storage_limit": int(storage_limit)})

    def recovery_watch_dir_add(self, directory: str) -> ApiResult:
        return self.post("/api/v1/recovery/watch-dirs", {"dir": directory})

    def recovery_watch_dir_remove(self, directory: str = "",
                                  index: int | None = None) -> ApiResult:
        body = {"dir": directory}
        if index is not None:
            body["index"] = int(index)
        return self.post("/api/v1/recovery/watch-dirs/delete", body)

    # ── 另外四个防护（tools.html 剩余卡片）──
    #
    # 注意：这四个 toggle 收的是**普通 dict**（`data: dict = Body(...)`），
    # 不是 ToggleRequest，所以**不需要** module 字段 —— 与 adblock /
    # urlguard / process-guard 那几个不同，别混。

    def honeypot_stats(self) -> ApiResult:
        """→ ``{enabled, catch_count, decoy_files[], recent_catches[]}``"""
        return self.get("/api/v1/honeypot/stats")

    def honeypot_toggle(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/honeypot/toggle", {"enabled": bool(enabled)})

    def browser_guard_stats(self) -> ApiResult:
        """→ ``{enabled, blocked_count, recent_blocks[]}``"""
        return self.get("/api/v1/browser-guard/stats")

    def browser_guard_toggle(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/browser-guard/toggle", {"enabled": bool(enabled)})

    def browser_guard_check(self) -> ApiResult:
        """→ ``{"issues": [...]}``"""
        return self.get("/api/v1/browser-guard/check")

    def camera_stats(self) -> ApiResult:
        """→ ``{enabled, blocked_count, whitelist[], recent_blocks[]}``"""
        return self.get("/api/v1/camera/stats")

    def camera_toggle(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/camera/toggle", {"enabled": bool(enabled)})

    def privacy_stats(self) -> ApiResult:
        """→ ``{enabled, trace_count, trace_types[]}``"""
        return self.get("/api/v1/privacy/stats")

    def privacy_toggle(self, enabled: bool) -> ApiResult:
        return self.post("/api/v1/privacy/toggle", {"enabled": bool(enabled)})

    # ── 隐私防护（补齐；之前只有 stats / toggle 两个）──
    # 后端签名（backend/app.py）：scan 无参、clean 收 {categories:[]}、
    # protect-files 收 {paths:[]}、sensitive-files 增删分别收 {path} 与 {id|path}。

    def privacy_scan(self) -> ApiResult:
        """扫描隐私痕迹 → {traces: [...], ...}"""
        return self.get("/api/v1/privacy/scan")

    def privacy_clean(self, categories: list | None = None) -> ApiResult:
        return self.post("/api/v1/privacy/clean",
                         {"categories": list(categories or [])})

    def privacy_access_log(self) -> ApiResult:
        """→ {logs: [...]}（后端无分页参数）"""
        return self.get("/api/v1/privacy/access-log")

    def privacy_sensitive_files(self) -> ApiResult:
        """→ {files: [{path}]}"""
        return self.get("/api/v1/privacy/sensitive-files")

    def privacy_sensitive_add(self, path: str) -> ApiResult:
        return self.post("/api/v1/privacy/sensitive-files", {"path": str(path)})

    def privacy_sensitive_delete(self, path: str) -> ApiResult:
        """后端优先取 id、其次回退 path —— 这里传 path。"""
        return self.post("/api/v1/privacy/sensitive-files/delete",
                         {"path": str(path)})

    def privacy_protect_files(self, paths: list | None = None) -> ApiResult:
        return self.post("/api/v1/privacy/protect-files",
                         {"paths": list(paths or [])})

    # ── 沙箱 ──
    # 注意 sandbox/status 是**无参**的（返回沙箱整体状态），不是 /status/{task_id}。

    def sandbox_status(self) -> ApiResult:
        return self.get("/api/v1/sandbox/status")

    def sandbox_history(self) -> ApiResult:
        """→ {history: [...]}"""
        return self.get("/api/v1/sandbox/history")

    def sandbox_stats(self) -> ApiResult:
        return self.get("/api/v1/sandbox/stats")

    def sandbox_analyze(self, file_path: str, timeout: int = 30) -> ApiResult:
        """同步分析，会阻塞到结束（可能几十秒）。长任务用 sandbox_analyze_job。"""
        return self.post("/api/v1/sandbox/analyze",
                         {"file_path": str(file_path), "timeout": int(timeout)})

    # ── 实时防护节流（rtguard）──
    # 主程序与 rtguard 是两个进程：后端转发到它的控制 API（默认 8022）。
    # rtguard 没跑时后端返回 available=False 且 **HTTP 200**（不报错），
    # 界面据此禁用按钮并给「启动」入口。

    def rtguard_status(self) -> ApiResult:
        """→ {available, level, label, target_pct, actual_pct, cores,
               budget_cores, levels:{low/medium/high:{label,pct}}, stats, ...}"""
        return self.get("/api/v1/rtguard/status")

    def rtguard_throttle(self, level: str) -> ApiResult:
        """切档 low(5%) / medium(10%) / high(15%)。
        rtguard 没跑时后端会**先拉起来再切**。"""
        return self.post("/api/v1/rtguard/throttle", {"level": str(level)})

    def rtguard_start(self, level: str | None = None) -> ApiResult:
        """拉起 rtguard；已在跑则返回 already_running=True，不重复起。"""
        return self.post("/api/v1/rtguard/start",
                         {"level": str(level)} if level else {})

    # ── 退出程序 ──
    # 走 _do_exit_with_fadeout：保存状态 → 释放引擎资源 → os._exit(0)。
    # **不可逆**，调用前必须让用户确认。

    def shutdown(self) -> ApiResult:
        return self.post("/api/v1/shutdown")

    # ── 白名单（文件/哈希级，policy_manager）──
    # 结构：{paths:[{path,note,added}], hashes:[{hash,path,note,added}],
    #        processes:[...], publishers:[...]}
    # ⚠️ add 的 category 只认 "paths" / "hashes"（见 app.py 的 whitelist_add）——
    #    传别的值后端会返回 {"error": ...}。

    def whitelist(self) -> ApiResult:
        return self.get("/api/v1/whitelist")

    def whitelist_add(self, category: str, value: str, note: str = "") -> ApiResult:
        """category ∈ paths(路径) / hashes(文件哈希；value 传文件路径，后端自己算 SHA256)"""
        return self.post("/api/v1/whitelist/add",
                         {"category": str(category), "value": str(value),
                          "note": str(note)})

    def whitelist_remove(self, category: str, value: str) -> ApiResult:
        return self.post("/api/v1/whitelist/remove",
                         {"category": str(category), "value": str(value)})

    def whitelist_check(self, path: str = "", file_hash: str = "") -> ApiResult:
        """→ {whitelisted: bool}"""
        return self.post("/api/v1/whitelist/check",
                         {"path": str(path), "hash": str(file_hash)})

    # ── 进程黑白名单（process_guard）──
    # get_lists → {blacklist:[名字...], whitelist:[名字...]}
    # 两边互斥：加进白名单会同时从黑名单摘掉，反之亦然（见 process_guard.py）。
    # 传的是**进程名**（如 notepad.exe），不是完整路径。

    def process_lists(self) -> ApiResult:
        return self.get("/api/v1/process-guard/lists")

    def process_blacklist_add(self, name: str) -> ApiResult:
        return self.post("/api/v1/process-guard/blacklist-add", {"name": str(name)})

    def process_blacklist_remove(self, name: str) -> ApiResult:
        return self.post("/api/v1/process-guard/blacklist-remove", {"name": str(name)})

    def process_whitelist_add(self, name: str) -> ApiResult:
        return self.post("/api/v1/process-guard/whitelist-add", {"name": str(name)})

    def process_whitelist_remove(self, name: str) -> ApiResult:
        # 这条路由是 2026-10-17 补的：原先只有 whitelist-add，加进去就撤不回来。
        return self.post("/api/v1/process-guard/whitelist-remove", {"name": str(name)})



def run_async(widget, work: Callable[[], Any],
              on_success: Callable[[Any], None] | None = None,
              on_error: Callable[[Exception], None] | None = None) -> threading.Thread:
    """后台线程执行 ``work()``，回调在主线程触发。

    ``widget`` 只用来取 ``after`` —— 任何 ``tk.Widget`` 都行。控件被销毁后
    ``after`` 会抛 ``TclError``，这里吞掉：那是正常的"页面已切换"竞态，
    不该让后台线程崩。
    """
    def _deliver(fn, arg):
        def _call():
            try:
                fn(arg)
            except Exception:
                # 回调自身的异常不该再往上冒（UI 已经不一致了，先别连累进程）
                pass
        try:
            widget.after(0, _call)
        except Exception:
            pass

    def _target():
        try:
            result = work()
        except Exception as exc:  # work 自己没兜住的，转成错误回调
            if on_error is not None:
                _deliver(on_error, exc)
            return
        if on_success is not None:
            _deliver(on_success, result)

    thread = threading.Thread(target=_target, daemon=True,
                              name=f"ui-io-{getattr(work, '__name__', 'task')}")
    thread.start()
    return thread


def fmt_size(num: Any) -> str:
    """字节数 → 人类可读。非法输入回退成 ``--``，不抛。"""
    try:
        value = float(num)
    except (TypeError, ValueError):
        return "--"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024.0 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return "--"


def fmt_int(num: Any) -> str:
    """整数千分位；非法输入 ``--``。"""
    try:
        return f"{int(num):,}"
    except (TypeError, ValueError):
        return "--"


def fmt_time(iso: Any) -> str:
    """ISO 时间串 → ``MM-DD HH:MM``；解析不了就原样截断返回。

    原实现用 ``date_part.partition("-")``，在**第一个**连字符处切分，
    于是 ``2026-10-05`` 取到的是 ``10-05`` 而不是月日里的某一段——
    返回值和文档字符串不符。改成显式按 ``-`` 拆成三段取后两段。
    """
    if not isinstance(iso, str) or not iso:
        return "--"
    text = iso.replace("T", " ")
    try:
        date_part, _, rest = text.partition(" ")
        bits = date_part.split("-")
        if len(bits) >= 3:
            short_date = f"{bits[1]}-{bits[2]}"
        else:
            short_date = date_part
        if rest:
            return f"{short_date} {rest[:5]}"
        return text[:16]
    except Exception:
        return text[:16]


def short_hash(value: Any, keep: int = 12) -> str:
    """哈希截断显示；空值返回 ``--``。"""
    if not isinstance(value, str) or not value:
        return "--"
    return value if len(value) <= keep else value[:keep] + "…"


def fmt_basename(value: Any, keep: int = 48) -> str:
    """取路径的文件名部分并限长；空值返回 ``--``。"""
    if not isinstance(value, str) or not value:
        return "--"
    name = value.replace("\\", "/").rsplit("/", 1)[-1] or value
    return name if len(name) <= keep else name[:keep - 1] + "…"

