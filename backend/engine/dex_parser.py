"""
DEX 字节码解析与 Android 恶意软件检测模块

解析 DEX 文件格式（Android Dalvik Executable），提取：
1. 字符串表 — 所有 MUTF-8 编码字符串
2. 方法签名 — 类名/方法名/原型信息
3. AndroRat 远控特征 — C2 地址、命令关键字、默认端口
4. iBanking 银行木马特征 — overlay 攻击、SMS 劫持
5. 通用 RAT 恶意指标评分

DEX 文件头格式（112 字节）：
  magic[8] | checksum(4) | signature(20) | file_size(4) | header_size(4)
  endian_tag(4) | link_size(4) | link_off(4) | map_off(4)
  string_ids_size(4) | string_ids_off(4) | type_ids_size(4) | type_ids_off(4)
  proto_ids_size(4) | proto_ids_off(4) | field_ids_size(4) | field_ids_off(4)
  method_ids_size(4) | method_ids_off(4) | class_defs_size(4) | class_defs_off(4)
  data_size(4) | data_off(4)
"""

import struct
import re
import os
from typing import Optional


# ── AndroRat 远控特征 ──────────────────────────────────────

# AndroRat 标志性字符串（作者信息、默认配置）
ANDRORAT_SIGNATURES = [
    b"AndroRat", b"com.androrat", b"com.my.androrat",
    b"androrat.server", b"androrat.client",
]

# AndroRat 默认端口（TCP Socket 连接）
ANDRORAT_PORTS = [5555, 4444, 6666, 8080, 1337]

# AndroRat 远控指令关键字（从 DEX 字符串表提取匹配）
ANDRORAT_COMMANDS = [
    b"getContacts", b"getSms", b"getCallLog", b"getLocation",
    b"startGPS", b"stopGPS", b"takePicture", b"takePhoto",
    b"recordAudio", b"recordCall", b"sendSMS", b"sendUssd",
    b"getInstalledApps", b"openUrl", b"getAccounts",
    b"uploadFile", b"downloadFile", b"deleteFile", b"listDir",
    b"shell", b"exec", b"getBattery", b"getNetwork",
    b"getWifi", b"getDeviceInfo", b"getSimInfo",
    b"getClipboard", b"setClipboard", b"vibrate",
    b"getSmsInbox", b"getSmsSent", b"monitorSms",
    b"getBookmarks", b"getHistory", b"getCookies",
    b"setWallpaper", b"showMessage", b"playSound",
    b"screenCapture", b"getProcess", b"killProcess",
    b"camera", b"microphone", b"gps", b"contacts",
    b"sms", b"call", b"photo", b"audio", b"video",
]

# iBanking 银行木马特征
IBANKING_SIGNATURES = [
    b"iBanking", b"com.ibanking", b"overlay_attack",
    b"inject_html", b"webinject", b"phishing_page",
    b"grab_passwords", b"steal_credentials",
    b"fake_login", b"html_injection",
]

# 通用 Android 恶意指标
GENERIC_ANDROID_MALICIOUS = [
    b"android.intent.action.BOOT_COMPLETED",  # 开机自启
    b"RECEIVE_SMS", b"READ_SMS", b"SEND_SMS",  # 短信劫持
    b"ACCESS_FINE_LOCATION", b"ACCESS_COARSE_LOCATION",  # 定位
    b"RECORD_AUDIO", b"CAMERA",  # 录音/拍照
    b"READ_CONTACTS", b"READ_CALL_LOG",  # 隐私读取
    b"PROCESS_OUTGOING_CALLS",  # 通话拦截
    b"SYSTEM_ALERT_WINDOW",  # 悬浮窗（overlay攻击）
    b"BIND_DEVICE_ADMIN",  # 设备管理器
    b"REQUEST_INSTALL_PACKAGES",  # 安装应用
    b"READ_PHONE_STATE",  # 读取IMEI
    b"com.metasploit.stage", b"metasploit",  # Metasploit payload
]

# C2 通信模式（IP:port / URL）
C2_PATTERNS = [
    rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}",  # IPv4:port
    rb"https?://[a-zA-Z0-9._-]+\.(com|net|org|io|cc|xyz|tk|ml|ga|cf)",  # 可疑域名
    rb"Socket\(", rb"HttpURLConnection", rb"URLConnection",
    rb"openConnection", rb"OutputStream", rb"InputStream",
    rb"DataOutputStream", rb"BufferedReader",
]


class DexParser:
    """DEX 文件格式解析器"""

    def __init__(self, data: bytes, file_path: str = ""):
        self.data = data
        self.file_path = file_path
        self.valid = False
        self._strings: list[str] = []
        self._methods: list[str] = []
        self._parse_header()

    # ── 头部解析 ──────────────────────────────────────

    def _parse_header(self):
        """解析 DEX 文件头，提取各表位置与大小"""
        if len(self.data) < 112:
            return
        if not self.data[:4] == b"dex\n":
            return
        unpack = struct.unpack_from
        self.string_ids_size  = unpack("<I", self.data, 56)[0]
        self.string_ids_off   = unpack("<I", self.data, 60)[0]
        self.type_ids_size    = unpack("<I", self.data, 64)[0]
        self.type_ids_off     = unpack("<I", self.data, 68)[0]
        self.proto_ids_size   = unpack("<I", self.data, 72)[0]
        self.proto_ids_off    = unpack("<I", self.data, 76)[0]
        self.field_ids_size   = unpack("<I", self.data, 80)[0]
        self.field_ids_off    = unpack("<I", self.data, 84)[0]
        self.method_ids_size  = unpack("<I", self.data, 88)[0]
        self.method_ids_off   = unpack("<I", self.data, 92)[0]
        self.class_defs_size  = unpack("<I", self.data, 96)[0]
        self.class_defs_off   = unpack("<I", self.data, 100)[0]
        self.data_size        = unpack("<I", self.data, 104)[0]
        self.data_off         = unpack("<I", self.data, 108)[0]

        # 加固/混淆文件的表偏移可能异常，加基本范围保护
        file_len = len(self.data)
        if self.string_ids_off + self.string_ids_size * 4 > file_len:
            return
        if self.method_ids_off + self.method_ids_size * 8 > file_len:
            return
        self.valid = True

    # ── 字符串提取 ──────────────────────────────────────────────────

    def extract_strings(self) -> list[str]:
        """从 DEX string_ids 表提取所有字符串（MUTF-8 解码）"""
        if not self.valid or self._strings:
            return self._strings
        off = self.string_ids_off
        count = min(self.string_ids_size, 50000)  # 防炸弹
        for i in range(count):
            try:
                s_off = struct.unpack_from("<I", self.data, off + i * 4)[0]
                s = self._read_mutf8(s_off)
                if s:
                    self._strings.append(s)
            except (struct.error, IndexError):
                break
        return self._strings

    def _read_mutf8(self, offset: int) -> str:
        """从 data 区读取 MUTF-8 字符串（先行 uleb128 长度）"""
        try:
            # uleb128 解码长度
            size = 0
            shift = 0
            idx = offset
            while idx < len(self.data):
                b = self.data[idx]
                idx += 1
                size |= (b & 0x7f) << shift
                shift += 7
                if not (b & 0x80):
                    break
                if shift > 35:  # 防爆炸
                    return ""
            if size <= 0 or idx + size > len(self.data):
                return ""
            raw = self.data[idx:idx + size]
            # MUTF-8 → UTF-8（处理代理对和 null 编码）
            return self._mutf8_to_str(raw)
        except (IndexError, struct.error):
            return ""

    @staticmethod
    def _mutf8_to_str(data: bytes) -> str:
        """简化 MUTF-8 → Python str（处理 null 终止和代理对）"""
        try:
            return data.decode("utf-8", errors="replace").rstrip("\0")
        except Exception:
            return data.decode("latin-1", errors="replace").rstrip("\0")

    # ── 方法签名提取 ────────────────────────────────────────────────

    def extract_methods(self) -> list[str]:
        """从 method_ids 表提取方法签名（类名 → 方法名）"""
        if not self.valid or self._methods:
            return self._methods
        strings = self.extract_strings()
        if not strings:
            return []
        off = self.method_ids_off
        count = min(self.method_ids_size, 100000)
        for i in range(count):
            try:
                entry = self.data[off + i * 8:off + i * 8 + 8]
                if len(entry) < 8:
                    break
                # type_idx(uint16) proto_idx(uint16) name_idx(uint32)
                type_idx = struct.unpack_from("<H", entry, 0)[0]
                name_idx = struct.unpack_from("<I", entry, 4)[0]
                cls = strings[type_idx] if type_idx < len(strings) else "?"
                name = strings[name_idx] if name_idx < len(strings) else "?"
                if cls != "?" or name != "?":
                    self._methods.append(f"{cls}->{name}")
            except (struct.error, IndexError):
                break
        return self._methods

    # ── 特征提取（AndroRat / iBanking / 通用恶意指标）──────────────

    def extract_features(self) -> dict:
        """提取 AndroRat / 通用 Android 恶意特征，返回特征字典"""
        strings = self.extract_strings()
        methods = self.extract_methods()

        # 合并所有可搜索的文本（大小写不敏感用 bytes）
        raw_data = self.data  # 原始字节搜索

        features: dict = {
            "strings_found": [],
            "commands_found": [],
            "malicious_indicators": [],
            "suspicious_methods": [],
            "c2_candidates": [],
            "score": 0,
        }

        # 1. AndroRat 标志性字符串
        for sig in ANDRORAT_SIGNATURES:
            if sig in raw_data:
                features["strings_found"].append(sig.decode(errors="replace"))
                features["score"] += 40
                break  # 只计一次

        # 2. iBanking 标志
        for sig in IBANKING_SIGNATURES:
            if sig in raw_data:
                features["strings_found"].append(sig.decode(errors="replace"))
                features["score"] += 35
                break

        # 3. AndroRat 命令关键字
        cmd_count = 0
        for cmd in ANDRORAT_COMMANDS:
            if cmd in raw_data:
                features["commands_found"].append(cmd.decode(errors="replace"))
                cmd_count += 1
        if cmd_count >= 5:
            features["score"] += 30
        elif cmd_count >= 3:
            features["score"] += 15
        elif cmd_count >= 1:
            features["score"] += 8

        # 4. 通用 Android 恶意权限/指标
        indicator_count = 0
        for ind in GENERIC_ANDROID_MALICIOUS:
            if ind in raw_data:
                features["malicious_indicators"].append(ind.decode(errors="replace"))
                indicator_count += 1
        if indicator_count >= 4:
            features["score"] += 20
        elif indicator_count >= 2:
            features["score"] += 10
        elif indicator_count >= 1:
            features["score"] += 5

        # 5. C2 通信模式
        for pat in C2_PATTERNS:
            if isinstance(pat, bytes):
                matches = re.findall(pat, raw_data)
            else:
                # 纯文本模式在 bytes 上搜索
                matches = [m for m in re.finditer(pat, raw_data)]
            for m in matches:
                decoded = m if isinstance(m, bytes) else m.group(0)
                decoded_s = decoded.decode(errors="replace") if isinstance(decoded, bytes) else decoded
                if decoded_s not in features["c2_candidates"]:
                    features["c2_candidates"].append(decoded_s)
        c2_count = len(features["c2_candidates"])
        if c2_count >= 3:
            features["score"] += 20
        elif c2_count >= 1:
            features["score"] += 8

        # 6. 可疑方法特征（调试/反射/动态加载）
        suspicious_patterns = [
            b"ClassLoader", b"DexClassLoader", b"PathClassLoader",
            b"loadClass", b"findClass", b"defineClass",
            b"invoke", b"getMethod", b"getDeclaredMethod",
            b"setAccessible", b"AccessibleObject",
            b"Runtime.exec", b"ProcessBuilder",
            b"openAssetFileDescriptor",
        ]
        for pat in suspicious_patterns:
            if pat in raw_data:
                features["suspicious_methods"].append(pat.decode(errors="replace"))
        if len(features["suspicious_methods"]) >= 3:
            features["score"] += 12
        elif len(features["suspicious_methods"]) >= 1:
            features["score"] += 5

        return features

    # ── 最终判定 ─────────────────────────────────────────────────

    def detect(self) -> Optional[dict]:
        """
        综合检测入口。
        返回 dict（含 threat_level / signature / details），或 None（安全/未识别）。
        """
        if not self.valid:
            return None

        feats = self.extract_features()
        score = feats["score"]

        # 确定检测结果
        if score >= 60:
            tl = "high"
            tag = "Android_RAT_High"
        elif score >= 30:
            tl = "medium"
            tag = "Android_RAT_Medium"
        elif score >= 15:
            tl = "low"
            tag = "Android_Suspicious"
        else:
            return None

        # 优先用 AndroRat/iBanking 命名
        name = "Android/Malware"
        for s in feats["strings_found"]:
            if "AndroRat" in s:
                name = "Android/AndroRAT"
                break
            if "iBanking" in s:
                name = "Android/iBanking"
                break

        abspath = os.path.abspath(self.file_path) if self.file_path else ""

        return {
            "path": abspath,
            "md5": "",
            "sha256": "",
            "threat_level": tl,
            "engine": "dex_analyzer",
            "signature": name,
            "category": "android_rat",
            "details": {
                "score": score,
                "strings_found": feats["strings_found"][:10],
                "commands_found": feats["commands_found"][:15],
                "malicious_indicators": feats["malicious_indicators"][:8],
                "suspicious_methods": feats["suspicious_methods"][:8],
                "c2_candidates": feats["c2_candidates"][:5],
                "method_count": len(self.extract_methods()),
                "string_count": len(self.extract_strings()),
            },
            "action": "quarantine",
        }
