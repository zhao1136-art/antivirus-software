"""
本地扫描引擎 - 文件遍历、哈希计算、启发式分析、特征库匹配
"""
import os
import re
import math
import hashlib
import zipfile
import tempfile
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import (
    SCAN_EXTENSIONS, EXCLUDED_DIRS, MAX_FILE_SIZE, MAX_WORKERS
)
from engine.signature_manager import SignatureManager
from engine.yara_scanner import YaraScanner
from engine.dex_parser import DexParser

# 递归解压扫描的安全上限（防 zip bomb）
_MAX_ARCHIVE_DEPTH = 4
_MAX_ARCHIVE_ENTRIES = 200
_MAX_ENTRY_SIZE = 50 * 1024 * 1024  # 单条目解压后上限 50MB
_ARCHIVE_EXTS = {".zip", ".apk", ".jar", ".rar"}
_ARCHIVE_MAGIC = {b"PK\x03\x04": "zip", b"PK\x05\x06": "zip", b"Rar!\x1a\x07": "rar"}


class LocalScanner:
    """本地文件扫描引擎"""

    def __init__(self, signature_manager: SignatureManager, yara_scanner: YaraScanner = None):
        self.sig_mgr = signature_manager
        self.yara = yara_scanner
        self._cancel_flag = threading.Event()

    def cancel(self):
        """取消当前扫描"""
        self._cancel_flag.set()

    def reset_cancel(self):
        self._cancel_flag.clear()

    def scan_paths(self, paths: list[str], scan_type: str = "quick",
                   progress_callback=None) -> dict:
        """
        扫描指定路径列表
        progress_callback(task_id, progress_percent, current_file) -> None
        返回扫描报告
        """
        self.reset_cancel()
        threats = []
        files_scanned = 0
        total_bytes = 0
        scanned_files = []  # 记录已扫描的文件路径（供云端补充查询）

        # 收集所有待扫描文件
        all_files = []
        for p in paths:
            if os.path.isfile(p):
                all_files.append(p)
            elif os.path.isdir(p):
                self._collect_files(p, all_files, scan_type)

        total_files = len(all_files)

        # 线程池并行扫描
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {}
            for file_path in all_files:
                if self._cancel_flag.is_set():
                    break
                future = executor.submit(self._scan_single_file, file_path)
                futures[future] = file_path

            completed = 0
            for future in as_completed(futures):
                if self._cancel_flag.is_set():
                    break
                completed += 1
                result = future.result()
                threats.extend(result)

                files_scanned += 1
                file_path = futures[future]
                scanned_files.append(file_path)
                try:
                    total_bytes += os.path.getsize(file_path)
                except Exception:
                    pass

                if progress_callback and total_files > 0:
                    progress_callback(
                        int(completed / total_files * 100),
                        file_path
                    )

        return {
            "scan_type": scan_type,
            "files_scanned": files_scanned,
            "total_files": total_files,
            "total_bytes": total_bytes,
            "threats_found": len(threats),
            "threats": threats,
            "_scanned_files": scanned_files,
            "cancelled": self._cancel_flag.is_set()
        }

    def _collect_files(self, directory: str, result: list, scan_type: str):
        """递归收集目录下的文件"""
        try:
            for entry in os.scandir(directory):
                if self._cancel_flag.is_set():
                    return
                try:
                    if entry.is_dir(follow_symlinks=False):
                        # 检查是否排除目录
                        dir_name = os.path.basename(entry.path)
                        if self._is_excluded_dir(entry.path, dir_name, scan_type):
                            continue
                        self._collect_files(entry.path, result, scan_type)
                    elif entry.is_file(follow_symlinks=False):
                        if self._should_scan_file(entry.path, scan_type):
                            result.append(entry.path)
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

    def _is_excluded_dir(self, path: str, dir_name: str, scan_type: str) -> bool:
        """判断目录是否需要排除"""
        if dir_name.startswith(".") or dir_name.startswith("$"):
            return True
        if dir_name in EXCLUDED_DIRS:
            return True
        # 快速扫描时跳过用户数据目录
        if scan_type == "quick":
            skip_dirs = {"AppData", "node_modules", "__pycache__", ".git",
                         "Windows.old", "PerfLogs", "Temp"}
            if dir_name in skip_dirs:
                return True
        return False

    def _should_scan_file(self, file_path: str, scan_type: str) -> bool:
        """判断文件是否需要扫描"""
        try:
            size = os.path.getsize(file_path)
            if size > MAX_FILE_SIZE or size == 0:
                return False
        except (OSError, PermissionError):
            return False

        if scan_type == "quick":
            # 快速扫描只关注可疑扩展名
            ext = os.path.splitext(file_path)[1].lower()
            all_sus = (SCAN_EXTENSIONS["executables"] |
                       SCAN_EXTENSIONS["scripts"] |
                       SCAN_EXTENSIONS["documents"])
            return ext in all_sus
        # 全盘/自定义扫描：所有文件
        return True

    def _scan_single_file(self, file_path: str) -> list:
        """扫描单个文件，返回威胁列表（含递归解压命中）。

        公开入口：始终返回 list[dict]，便于上层用 extend 聚合，
        也支持一个归档文件解压出多个内部威胁。
        """
        return self._scan_single_file_impl(file_path, depth=0)

    def _scan_single_file_impl(self, file_path: str, depth: int = 0) -> list:
        """扫描单个文件（含递归解压）；返回威胁列表（可能为空）"""
        threats: list = []
        try:
            size = os.path.getsize(file_path)
            if size > MAX_FILE_SIZE or size == 0:
                return threats
        except (OSError, PermissionError):
            return threats

        # 0. 递归解压扫描（受深度/条目上限保护，防 zip bomb）
        if depth < _MAX_ARCHIVE_DEPTH:
            arc_type = self._detect_archive(file_path, size)
            if arc_type and arc_type == "zip":
                # APK 走专用路径（classes.dex → DexParser + YARA），非 APK 走通用解压
                if self._is_apk(file_path):
                    apk_threats = self._scan_apk(file_path, depth)
                    if apk_threats:
                        return apk_threats
                inner = self._unpack_and_scan(file_path, arc_type, depth)
                if inner:
                    return inner

        # 1. 计算哈希
        md5_hash, sha256_hash = self._compute_hashes(file_path)
        if not md5_hash and not sha256_hash:
            return threats

        # 2. 特征库匹配
        sig = self.sig_mgr.lookup(md5=md5_hash, sha256=sha256_hash)
        if sig:
            threats.append({
                "path": os.path.abspath(file_path),
                "md5": md5_hash,
                "sha256": sha256_hash,
                "threat_level": sig["threat_level"],
                "engine": "signature",
                "signature": sig["threat_name"],
                "category": sig["category"],
                "details": {
                    "matched_hash": sig["matched_hash"],
                    "source": sig["source"],
                    "file_size": size
                },
                "action": "quarantine"
            })
            return threats

        # 3. YARA 规则匹配
        if self.yara and self.yara.rules:
            yara_hits = self.yara.scan_file(file_path)
            if yara_hits:
                # 取威胁等级最高的命中
                level_map = {"RANSOMWARE": "critical", "BACKDOOR": "high", "INFOSTEALER": "high",
                             "BANKING": "high", "MALWARE": "high", "TROJAN": "high",
                             "HACKTOOL": "medium", "INFO": "low"}
                best = yara_hits[0]
                yara_level = level_map.get(best.get("malware_type", ""), "medium")
                threats.append({
                    "path": os.path.abspath(file_path),
                    "md5": md5_hash,
                    "sha256": sha256_hash,
                    "threat_level": yara_level,
                    "engine": "yara",
                    "signature": f"YARA.{best['rule']}",
                    "category": best.get("malware_type", "MALWARE").lower(),
                    "details": {
                        "rule": best["rule"],
                        "description": best["description"],
                        "matched_patterns": best["matched_patterns"],
                        "yara_source": best.get("source_file", ""),
                        "file_size": size
                    },
                    "action": "quarantine"
                })
                return threats

        # 4. 通用启发式分析（所有文件类型）
        generic = self._generic_heuristic(file_path, md5_hash, sha256_hash, size)
        if generic:
            threats.append(generic)
            return threats

        # 5. 启发式分析（PE 文件）
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SCAN_EXTENSIONS["executables"]:
            heuristic = self._pe_heuristic(file_path, md5_hash, sha256_hash, size)
            if heuristic:
                threats.append(heuristic)
                return threats

        # 6. ML 引擎检测（PE 文件）
        if ext in SCAN_EXTENSIONS["executables"]:
            ml_result = self._ml_scan(file_path, md5_hash, sha256_hash, size)
            if ml_result:
                threats.append(ml_result)
                return threats

        return threats

    # ── APK 专用检测路径 ─────────────────────────────────────────

    @staticmethod
    def _is_apk(file_path: str) -> bool:
        """判断文件是否为 APK（扩展名 .apk 或 zip 内含 classes.dex）"""
        if os.path.splitext(file_path)[1].lower() == ".apk":
            return True
        # zip 但含 classes.dex → 也按 APK 处理
        try:
            with zipfile.ZipFile(file_path) as zf:
                names = zf.namelist()
                return any("classes.dex" in n for n in names)
        except Exception:
            return False

    def _scan_apk(self, file_path: str, depth: int) -> list:
        """APK 专用扫描：解压提取 classes.dex → DexParser 分析 + YARA 扫描"""
        threats: list = []
        tmpdir = None
        try:
            zf = zipfile.ZipFile(file_path)
            # 查找 classes.dex（可能有多个 multidex）
            dex_entries = [n for n in zf.namelist()
                           if n.endswith("classes.dex") or n.endswith(".dex")]
            if not dex_entries:
                return threats

            tmpdir = tempfile.mkdtemp(prefix="andun_apk_")
            abspath = os.path.abspath(file_path)

            for dex_name in dex_entries[:5]:  # 最多处理 5 个 dex
                info = zf.getinfo(dex_name)
                if info.file_size > _MAX_ENTRY_SIZE:
                    continue
                dest = os.path.join(tmpdir, os.path.basename(dex_name) or "classes.dex")
                with zf.open(info) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out, 65536)

                # 1. DexParser 特征分析
                try:
                    with open(dest, "rb") as f:
                        dex_data = f.read()
                    dp = DexParser(dex_data, file_path)
                    result = dp.detect()
                    if result:
                        result["path"] = abspath
                        result.setdefault("details", {})["extracted_from"] = dex_name
                        threats.append(result)
                except Exception:
                    pass

                # 2. YARA 扫描 DEX 字节码
                if self.yara and self.yara.rules:
                    try:
                        yara_hits = self.yara.scan_file(dest)
                        if yara_hits:
                            level_map = {
                                "RANSOMWARE": "critical", "BACKDOOR": "high",
                                "INFOSTEALER": "high", "BANKING": "high",
                                "MALWARE": "high", "TROJAN": "high",
                                "HACKTOOL": "medium", "INFO": "low",
                            }
                            for hit in yara_hits:
                                yl = level_map.get(hit.get("malware_type", ""), "medium")
                                threats.append({
                                    "path": abspath,
                                    "md5": "", "sha256": "",
                                    "threat_level": yl,
                                    "engine": "yara",
                                    "signature": f"YARA.{hit['rule']}",
                                    "category": hit.get("malware_type", "MALWARE").lower(),
                                    "details": {
                                        "rule": hit["rule"],
                                        "description": hit.get("description", ""),
                                        "matched_patterns": hit.get("matched_patterns", []),
                                        "extracted_from": dex_name,
                                    },
                                    "action": "quarantine",
                                })
                    except Exception:
                        pass

                if self._cancel_flag.is_set():
                    break

        except Exception:
            pass
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
        return threats

    def _detect_archive(self, file_path: str, size: int) -> str | None:
        """按文件头 magic / 扩展名判断归档类型；返回 'zip'/'rar'/None"""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(8)
        except (OSError, PermissionError):
            return None
        for sig, t in _ARCHIVE_MAGIC.items():
            if magic.startswith(sig):
                return t
        ext = os.path.splitext(file_path)[1].lower()
        if ext in _ARCHIVE_EXTS:
            return "zip" if ext != ".rar" else "rar"
        return None

    def _unpack_and_scan(self, file_path: str, arc_type: str, depth: int) -> list:
        """解压归档并递归扫描内部条目；返回内部威胁列表（path 重写回原始归档）。

        仅支持 zip 系列（zip/apk/jar，标准库 zipfile）。rar 需要第三方库，暂不展开。
        """
        if arc_type != "zip":
            return []
        try:
            zf = zipfile.ZipFile(file_path)
        except Exception:
            return []
        tmp = tempfile.mkdtemp(prefix="andun_unpack_")
        found: list = []
        try:
            entries = zf.infolist()
            if len(entries) > _MAX_ARCHIVE_ENTRIES:
                # 条目过多 → 疑似 zip bomb，直接不展开
                return []
            for info in entries:
                if info.is_dir():
                    continue
                name = info.filename
                # 防路径穿越
                if name.startswith("/") or name.startswith("\\") or ".." in name:
                    continue
                if info.file_size > _MAX_ENTRY_SIZE:
                    continue
                try:
                    dest = os.path.join(tmp, os.path.basename(name) or "_entry")
                    with zf.open(info) as src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out, 65536)
                except Exception:
                    continue
                res = self._scan_single_file_impl(dest, depth + 1)
                for t in res:
                    # 把命中归属回原始归档，保证按家族统计正确
                    t["path"] = os.path.abspath(file_path)
                    t.setdefault("details", {})["extracted_from"] = name
                    found.append(t)
                if self._cancel_flag.is_set():
                    break
        except Exception:
            pass
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return found

    def _compute_hashes(self, file_path: str) -> tuple[str, str]:
        """计算 MD5 和 SHA256"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except (OSError, PermissionError):
            return "", ""

    def _generic_heuristic(self, file_path: str, md5: str, sha256: str, size: int) -> dict | None:
        """
        通用文件启发式检测（不依赖 PE 格式，对所有文件生效）
        检查：熵值、勒索软件特征字符串、恶意脚本模式等
        """
        try:
            # 读取文件头部（前 64KB 检测内容特征）
            with open(file_path, "rb") as f:
                header = f.read(65536)

            if not header:
                return None

            score = 0
            reasons = []

            # --- 1. 熵值检测（加密/加壳/混淆文件）---
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

            # --- 2. 勒索软件/恶意通知特征字符串（大写ASCII文本块）---
            text_chunks = re.findall(rb'[\x20-\x7E]{20,}', header)
            ransom_signals = [b"YOUR FILES", b"ENCRYPTED", b"BITCOIN", b"DECRYPT",
                              b"YOUR DOCUMENTS", b"YOUR DATA", b"PAYMENT",
                              b"PRIVATE KEY", b"RANSOM", b"LOCKED",
                              b"RECOVERY KEY", b"WALLET ADDRESS"]
            for chunk in text_chunks:
                upper = chunk.upper()
                for sig in ransom_signals:
                    if sig in upper:
                        score += 30
                        reasons.append("勒索特征文本: %s" % sig.decode())
                        break

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
                # 大文件无识别头 → 可能是 shellcode 或原始载荷
                score += 15
                reasons.append("无可识别文件头")

            # --- 5. 脚本类恶意模式（.js/.vbs/.hta/.ps1/.wsf/.jse）---
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

            # --- 6. Office 宏 / OLE 可疑结构（.doc/.xls/.ppt/.docm 等）---
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

            # --- 8. 驱动/ActiveX 原始 blob（.sys/.ocx/.drv 无 MZ 头）---
            drv_exts = (".sys", ".ocx", ".drv")
            if fname_l.endswith(drv_exts) and header[:2] != b"MZ":
                drv_sigs = [b"DriverEntry", b"DllRegisterServer", b"DllUnregisterServer",
                            b"IoCreateDevice", b"Zw", b"Nt", b"IRQL", b"\\Driver\\",
                            b"Mm", b"ExAllocatePool", b"PsCreateSystemThread"]
                if any(s in header for s in drv_sigs):
                    score += 30
                    reasons.append("驱动/ActiveX原始blob特征")

            # --- 9. Android APK / DEX 恶意指标（后续可独立扩展）---
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
        except Exception:
            pass
        return None

    def _pe_heuristic(self, file_path: str, md5: str, sha256: str, size: int) -> dict | None:
        """PE 文件启发式检测"""
        try:
            with open(file_path, "rb") as f:
                header = f.read(64)
        except (OSError, PermissionError):
            return None

        if len(header) < 2:
            return None

        # 检查 MZ 头
        if header[:2] != b"MZ":
            return None

        # 简单启发式检查
        warnings = []
        score = 0

        # 1. PE 头偏移异常
        if len(header) >= 64:
            pe_offset = int.from_bytes(header[60:64], "little")
            if pe_offset < 64 or pe_offset > 4096:
                warnings.append("异常 PE 头偏移")
                score += 30

        # 2. 文件大小可疑（< 10KB 的可执行文件较少）
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

    def _ml_scan(self, file_path: str, md5: str, sha256: str, size: int) -> dict | None:
        """使用 ML 引擎扫描 PE 文件"""
        try:
            from engine.ml_scanner import scan_pe as ml_scan_pe
            with open(file_path, "rb") as f:
                data = f.read()
            result = ml_scan_pe(data)
            verdict = result.get("verdict", "CLEAN")
            confidence = result.get("confidence", 0.0)

            if verdict == "MALICIOUS":
                threat_level = "critical" if confidence >= 0.85 else "high"
                return {
                    "path": os.path.abspath(file_path),
                    "md5": md5,
                    "sha256": sha256,
                    "threat_level": threat_level,
                    "engine": "ml",
                    "signature": f"ML.{verdict}",
                    "category": "ml_detected",
                    "details": {
                        "ml_verdict": verdict,
                        "ml_confidence": confidence,
                        "ml_reasons": result.get("reasons", []),
                        "suspicious_apis": result.get("features", {}).get("suspicious_apis", []),
                        "pe_info": result.get("features", {}).get("pe_info", {}),
                        "file_size": size
                    },
                    "action": "quarantine"
                }
            elif verdict == "SUSPICIOUS":
                return {
                    "path": os.path.abspath(file_path),
                    "md5": md5,
                    "sha256": sha256,
                    "threat_level": "medium",
                    "engine": "ml",
                    "signature": f"ML.{verdict}",
                    "category": "ml_suspicious",
                    "details": {
                        "ml_verdict": verdict,
                        "ml_confidence": confidence,
                        "ml_reasons": result.get("reasons", []),
                        "suspicious_apis": result.get("features", {}).get("suspicious_apis", []),
                        "pe_info": result.get("features", {}).get("pe_info", {}),
                        "file_size": size
                    },
                    "action": "prompt"
                }
        except Exception:
            pass
        return None
