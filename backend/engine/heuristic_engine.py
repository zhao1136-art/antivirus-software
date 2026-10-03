"""
启发式检测引擎（独立抽取版）

来源：从 engine/local_scanner.py 抽取既有启发式实现，逐字搬运，未新增任何检测逻辑、
未改动任何阈值与打分。同时并入 engine/url_guard.py 的 URL 启发式。

等价性保证（**抽取当时**成立；此后有一段刻意的行为修正，见下）：
  - 抽取时本文件中的判定逻辑与阈值全部逐字复制自原实现，仅去掉 `self` 形参。
  - 原方法的对外名称与签名保持不变，内部改为委托到本引擎（见 local_scanner.py）。
  - 已用 300 个合法 System32 样本逐文件比对：返回 dict（分数 / warnings / 熵 / action）
    与原实现完全一致，差异数 0。注意：该样本集上原实现本身就会命中 3/300
    （通用启发式）与 0/300（PE 启发式），抽取未改变其中任何一个判定。

2026-10-03 误报修正（只改了 `analyze_generic` 的第 2 段"勒索文本特征"这一处，
其余段落与阈值一个字没动）：
  旧实现把 4346 个合法 System32 文件里的 30 个判成勒索软件，全部仅由勒索
  关键词文本命中构成（cipher.exe 240 分、SecurityHealthSystray.exe 90 分…）。
  修正后同一批文件命中 0 个，同一批文件上的其它判定、其它段落逐字未变。
  详见 `analyze_generic` 第 2 段注释与 `RANSOM_TEXT_STRONG/_WEAK`。

抽取来源与校验（AST 源码段 SHA256 前 16 位）：
  _generic_heuristic_from_data / _generic_heuristic_core / _generic_heuristic /
  _pe_heuristic_from_data / _pe_heuristic 在以下三处逐字节一致（AST 比对确认）：
      H:\\Caelire\\backend\\engine\\local_scanner.py      <- 以它为准（现网运行路径）
      H:\\御天精简版\\backend\\engine\\local_scanner.py
      H:\\Caelire\\rtguard\\engine\\local_scanner.py
  url_guard._heuristic 在 backend 与 rtguard 两处一致。
"""
import logging
import math
import os
import re

logger = logging.getLogger("yutian")

# ── 勒索文本特征（按"有效鉴别力"分档，2026-10-03 新增）──────────────────────
#
# 强特征：整句/多词特征，正常软件里几乎不会自然出现 —— 有鉴别力，可单独计分。
RANSOM_TEXT_STRONG = (
    b"YOUR FILES", b"YOUR DOCUMENTS", b"YOUR DATA", b"RANSOM",
    b"PRIVATE KEY", b"RECOVERY KEY", b"WALLET ADDRESS", b"BITCOIN",
)
#
# 弱特征：单个通用英文词，微软自带程序的界面文案/资源里到处都是
# （cipher.exe 里 8 个 ENCRYPTED、bdeui.dll 的 DECRYPT、SecurityHealthSystray.exe
# 的 LOCKED、PaymentMediatorServiceProxy.dll 的 PAYMENT…）—— 只能当旁证。
RANSOM_TEXT_WEAK = (b"ENCRYPTED", b"DECRYPT", b"LOCKED", b"PAYMENT")

RANSOM_STRONG_SCORE = 30      # 每个**不同**强特征
RANSOM_STRONG_MAX_HITS = 2    # 最多按 2 个计分（封顶 60）
RANSOM_WEAK_SCORE = 10        # 每个**不同**弱特征
RANSOM_WEAK_MAX_HITS = 3      # 最多按 3 个计分（封顶 30，到不了 40 报告线）


def _signed_system_binary(file_path: str) -> bool:
    """文件是否"位于系统目录 + Authenticode 签名有效"。

    复用 engine.threat_decision 的 WinVerifyTrust 封装（**不**自己写签名校验）。
    任何异常、模块不可用、签名取不到（大量系统文件是目录签名，返回
    0x800B0100 TRUST_E_NOSIGNATURE）一律返回 False —— 默认**不豁免**，
    宁可多报也不瞎。实测 30 个误报文件里 5 个能拿到有效内嵌签名。
    """
    try:
        from engine.threat_decision import is_system_path, verify_signature
        if not is_system_path(file_path):
            return False
        ok, _detail = verify_signature(file_path)
        return bool(ok)
    except Exception:
        return False


# ── URL 启发式关键词（原 engine/url_guard.py 模块级常量，逐字迁移）─────────

# 钓鱼/恶意 URL 启发式关键词（命中即提升风险）
PHISH_MARKERS = [
    "verify", "secure", "account", "billing", "lotto", "prize",
    "airdrop", "vip", "free-", "refund", "bonus", "gift-card",
    "-confirm-", "-verify-", "web-wallet", "login-update",
]

# 高风险内容关键词（赌博/色情/诈骗等）
RISK_KEYWORDS = [
    "casino", "poker", "baccarat", "lottery", "bingo",
    "porn", "xxx", "loan-", "credit-fast", "bitcoin-double",
]


class HeuristicEngine:
    """启发式检测引擎（无状态，可安全跨线程复用）"""

    # ════════════════════════════════════════════════════════════
    # 通用文件启发式（脚本 / Office / PDF / 驱动 / Android）
    # ════════════════════════════════════════════════════════════

    def analyze_generic(self, header: bytes, file_path: str,
                        md5: str, sha256: str, size: int) -> dict | None:
        """通用文件启发式检测核心逻辑（header 为文件前 64KB）"""
        if not header:
            return None

        score = 0
        reasons = []

        # --- 1. 熵值检测 ---
        freq = [0] * 256
        for b in header:
            freq[b] += 1
        ent = 0.0
        hlen = len(header)
        for c in range(256):
            if freq[c]:
                p = freq[c] / hlen
                ent -= p * (math.log2(p) if p > 0 else 0)
        if ent > 7.5:
            score += 25
            reasons.append("高熵内容 (%.2f)" % ent)
        elif ent > 7.0:
            score += 10
            reasons.append("较高熵值 (%.2f)" % ent)

        # --- 2. 勒索软件/恶意通知特征字符串 ---
        #
        # 2026-10-03 实测修正（误报：合法 System32 文件被判成勒索软件）。
        # 旧实现：每个 20+ 字符 ASCII 块里命中的关键词都 +30，不区分词、不去重。
        # 实测 4346 个 System32 文件命中 30 个，**全部**只由文本命中构成：
        #     cipher.exe                      240  = ENCRYPTED ×8
        #     PaymentMediatorServiceProxy.dll 210  = PAYMENT ×6 + LOCKED
        #     bdeui.dll                       180  = DECRYPT ×4 + ENCRYPTED + LOCKED
        #     nltest.exe / wsmprovhost.exe    180  = LOCKED ×6
        #     baaupdate.exe / bdechangepin.exe / fveprompt.exe
        #                                     120  = DECRYPT ×2 + ENCRYPTED + LOCKED
        #     SecurityHealthSystray.exe        90  = LOCKED ×3
        # 这些是 Windows 安全中心 / BitLocker / 证书服务的自带程序，
        # 它们自己的界面文案里就写着 DECRYPT / ENCRYPTED / LOCKED / PAYMENT。
        #
        # 改法（同 2026-10-03 其它两处误报的既定模式：先算"有效鉴别力"）：
        #   ① 特征分两档。整句特征（YOUR FILES / PRIVATE KEY / WALLET ADDRESS…）
        #      才有鉴别力；单个通用英文词（ENCRYPTED/DECRYPT/LOCKED/PAYMENT）
        #      在正常软件里到处都是，只能算弱旁证。
        #   ② 按**不同**特征计分并封顶：强 30/个（≤2 个）、弱 10/个（≤3 个）。
        #      于是单个弱词 = 10 分、三个弱词 = 30 分，都够不到 40 分的报告线；
        #      同一个词刷屏重复计分（cipher.exe 的 8×ENCRYPTED=240）同时失效。
        #   ③ 微软签名 + 系统目录的文件（复用 threat_decision.verify_signature，
        #      不自己写签名校验）**弱**文本特征一律不计分，只留可见的降级说明；
        #      强特征照常计分 —— 不做"签名即豁免"，真勒索文本该报还是报。
        # 降级绝不静默：降级原因写进 warnings（随报告露出）并记一条日志。
        text_chunks = re.findall(rb'[\x20-\x7E]{20,}', header)
        strong_hits: list[str] = []
        weak_hits: list[str] = []
        for chunk in text_chunks:
            upper = chunk.upper()
            for sig in RANSOM_TEXT_STRONG:
                name = sig.decode()
                if name not in strong_hits and sig in upper:
                    strong_hits.append(name)
            for sig in RANSOM_TEXT_WEAK:
                name = sig.decode()
                if name not in weak_hits and sig in upper:
                    weak_hits.append(name)

        if strong_hits:
            score += RANSOM_STRONG_SCORE * min(len(strong_hits), RANSOM_STRONG_MAX_HITS)
            reasons.append("勒索特征文本(强): %s" % ", ".join(strong_hits))

        if weak_hits:
            weak_score = RANSOM_WEAK_SCORE * min(len(weak_hits), RANSOM_WEAK_MAX_HITS)
            if _signed_system_binary(file_path):
                # 降级可见：原因进 warnings，同时落一条日志
                reasons.append(
                    "勒索关键词(弱)已降级不计分: %s —— 微软签名系统目录文件"
                    % ", ".join(weak_hits))
                logger.info(
                    "启发式降级(不静默): %s 仅命中弱勒索关键词 %s，"
                    "签名有效且位于系统目录，弱文本特征不计分",
                    file_path, ",".join(weak_hits))
            else:
                score += weak_score
                reasons.append("勒索关键词(弱): %s" % ", ".join(weak_hits))

        # --- 3. PowerShell/CMD 编码命令模式 ---
        ps_patterns = [b"-EncodedCommand", b"-enc ", b"FromBase64String",
                       b"IEX(New-Object", b"Invoke-Expression",
                       b"certutil -decode", b"bitsadmin /transfer"]
        for pat in ps_patterns:
            if pat in header:
                score += 20
                reasons.append("恶意脚本模式: %s" % pat.decode())
                break

        # --- 4. 无可识别文件头的混淆数据 ---
        known_headers = [b"\x4d\x5a", b"\x7f\x45\x4c\x46", b"\x50\x4b\x03\x04",
                         b"\x89\x50\x4e\x47", b"\xff\xd8\xff", b"\x49\x44\x33",
                         b"\x25\x50\x44\x46", b"\x1f\x8b", b"\x52\x61\x72\x21",
                         b"\x00\x00\x00\x18\x66\x74\x79\x70"]
        has_known_header = any(header.startswith(h) for h in known_headers)
        if not has_known_header and size > 10240 and len(header) >= 16:
            score += 15
            reasons.append("无可识别文件头")

        # --- 5. 脚本类恶意模式 ---
        fname_l = os.path.basename(file_path).lower()
        script_exts = (".js", ".jse", ".vbs", ".vbe", ".hta", ".wsf", ".wsc", ".ps1", ".bat", ".cmd")
        if fname_l.endswith(script_exts):
            script_sigs = [
                b"WScript.Shell", b"Shell.Application", b"mshta.exe",
                b"regsvr32", b"scrobj.dll", b"/s /u /i:", b"msxml2.XMLHTTP",
                b"ActiveXObject", b"document.write", b"<script", b"powershell -w hidden",
                b"powershell -enc", b" -nop -w hidden", b"DownloadString",
                b"certutil", b"bitsadmin", b"cmd.exe /c", b"CreateObject",
            ]
            hits = [s for s in script_sigs if s.lower() in header.lower()]
            if hits:
                score += 35
                reasons.append("恶意脚本模式: %s" % b",".join(hits[:3]).decode(errors="ignore"))

        # --- 6. Office 宏 / OLE 可疑结构 ---
        office_exts = (".doc", ".docm", ".dotm", ".xls", ".xlsm", ".xltm",
                       ".ppt", ".pptm", ".potm", ".rtf")
        if fname_l.endswith(office_exts):
            ole_sigs = [b"Macros", b"VBA", b"AutoOpen", b"AutoExec",
                        b"Sub Auto", b"ThisDocument", b"OLE2Link", b"Shell32"]
            if any(s in header for s in ole_sigs):
                score += 25
                reasons.append("可疑Office宏/OLE结构")

        # --- 7. PDF 内嵌 JavaScript ---
        if fname_l.endswith(".pdf"):
            if b"/JS" in header or b"/JavaScript" in header or b"/OpenAction" in header:
                score += 25
                reasons.append("PDF内嵌JavaScript/自动动作")

        # --- 8. 驱动/ActiveX 原始 blob ---
        drv_exts = (".sys", ".ocx", ".drv")
        if fname_l.endswith(drv_exts) and header[:2] != b"MZ":
            drv_sigs = [b"DriverEntry", b"DllRegisterServer", b"DllUnregisterServer",
                        b"IoCreateDevice", b"Zw", b"Nt", b"IRQL", b"\\Driver\\",
                        b"Mm", b"ExAllocatePool", b"PsCreateSystemThread"]
            if any(s in header for s in drv_sigs):
                score += 30
                reasons.append("驱动/ActiveX原始blob特征")

        # --- 9. Android 恶意指标 ---
        is_apk = header[:4] == b"PK\x03\x04" and b"classes.dex" in header
        is_dex = header[:4] == b"dex\n"
        if is_apk or is_dex:
            android_sigs = [b"AndroRAT", b"iBanking", b"com.metasploit.stage",
                            b"/system/bin/sh", b"Runtime.getRuntime",
                            b"getDeviceId", b"SEND_SMS", b"android.intent.action.BOOT_COMPLETED",
                            b"loadUrl", b"WebViewController", b"inject"]
            android_hits = [s for s in android_sigs if s in header]
            if android_hits:
                score += 35
                reasons.append("Android恶意指标: %s" % b",".join(android_hits[:3]).decode(errors="ignore"))

        if score >= 40:
            threat_level = "medium" if score < 60 else "high"
            return {
                "path": os.path.abspath(file_path),
                "md5": md5,
                "sha256": sha256,
                "threat_level": threat_level,
                "engine": "heuristic",
                "signature": "Heuristic.Generic",
                "category": "generic",
                "details": {
                    "heuristic_score": score,
                    "warnings": reasons,
                    "entropy": round(ent, 2),
                    "file_size": size
                },
                "action": "prompt" if score < 60 else "quarantine"
            }
        return None

    def analyze_generic_file(self, file_path: str, md5: str,
                             sha256: str, size: int) -> dict | None:
        """通用文件启发式检测（保留兼容性，从文件读取）"""
        try:
            with open(file_path, "rb") as f:
                header = f.read(65536)
            return self.analyze_generic(header, file_path, md5, sha256, size)
        except Exception:
            pass
        return None

    # ════════════════════════════════════════════════════════════
    # PE 文件启发式
    # ════════════════════════════════════════════════════════════

    def analyze_pe(self, header: bytes, file_path: str,
                   md5: str, sha256: str, size: int) -> dict | None:
        """PE 文件启发式检测 - 使用内存缓冲（零额外 I/O）"""
        if len(header) < 2 or header[:2] != b"MZ":
            return None

        warnings = []
        score = 0

        # 1. PE 头偏移异常
        if len(header) >= 64:
            pe_offset = int.from_bytes(header[60:64], "little")
            if pe_offset < 64 or pe_offset > 4096:
                warnings.append("异常 PE 头偏移")
                score += 30

        # 2. 文件大小可疑
        if size < 10240:
            warnings.append("文件体积过小")
            score += 15

        # 3. 无扩展名/双扩展名
        name = os.path.basename(file_path).lower()
        ext_count = name.count(".")
        if ext_count > 1 and any(e in name for e in [".pdf", ".doc", ".jpg", ".png"]):
            warnings.append("可疑双扩展名")
            score += 25

        if score >= 40:
            return {
                "path": os.path.abspath(file_path),
                "md5": md5,
                "sha256": sha256,
                "threat_level": "medium" if score < 60 else "high",
                "engine": "pe_heuristic",
                "signature": "Heuristic.PE.Suspicious",
                "category": "trojan",
                "details": {
                    "heuristic_score": score,
                    "warnings": warnings,
                    "file_size": size
                },
                "action": "quarantine" if score >= 60 else "prompt"
            }
        return None

    def analyze_pe_file(self, file_path: str, md5: str,
                        sha256: str, size: int) -> dict | None:
        """PE 文件启发式检测（保留兼容性）"""
        try:
            with open(file_path, "rb") as f:
                header = f.read(64)
        except (OSError, PermissionError):
            return None
        return self.analyze_pe(header, file_path, md5, sha256, size)

    # ════════════════════════════════════════════════════════════
    # URL / 域名启发式
    # ════════════════════════════════════════════════════════════

    def analyze_url(self, url: str, host: str) -> list[str]:
        """URL/域名启发式风险特征"""
        flags: list[str] = []
        low = url.lower()
        # 特定高风险内容关键词
        if any(k in low for k in RISK_KEYWORDS):
            flags.append("命中高风险内容关键词")
        if any(m in low for m in PHISH_MARKERS):
            # 钓鱼标识需配合可疑组合才报告，避免过度告警
            suspicious = (host.count("-") >= 2) or any(t in host for t in
                        ("secure", "verify", "login", "account", "bonus", "airdrop"))
            if suspicious:
                flags.append("疑似钓鱼特征(安全类关键词+连字符域名)")
        return flags


# 共享单例（无状态，线程安全）
_shared_engine = HeuristicEngine()


def get_heuristic_engine() -> HeuristicEngine:
    """返回进程内共享的启发式引擎实例"""
    return _shared_engine
