"""
御天洞渊引擎 - 整合 capa / PE-sieve / ClamAV / yarGen / libpeconv（深察渊底，剖析毫芒）
对可疑文件进行行为分析、内存扫描、多引擎查杀、YARA规则生成
"""
import os
import json
import subprocess
import threading
import sys

_ANALYZER_DIR = os.path.dirname(os.path.abspath(__file__))
_STATUS = {"scanning": False, "current_file": "", "result": None}

def status() -> dict:
    return dict(_STATUS)


# ===================== 引擎状态检查 =====================

def engines_status() -> dict:
    """返回所有引擎的可用状态"""
    result = {}
    
    # capa
    try:
        import capa.main
        result["capa"] = {"available": True, "type": "行为分析", "desc": "FLARE capa - ATT&CK 行为映射"}
    except ImportError:
        result["capa"] = {"available": False, "type": "行为分析", "desc": "未安装: pip install flare-capa",
                          "source": os.path.join(os.path.dirname(_ANALYZER_DIR), "..", "capa-master", "capa-master")}
    
    # yarGen
    yargen_path = os.path.join(_ANALYZER_DIR, "yarGen.py")
    result["yarGen"] = {"available": os.path.isfile(yargen_path), "type": "规则生成",
                        "desc": "YARA 规则自动生成工具 v0.25.0"}
    
    # PE-sieve
    native_dir = os.path.join(_ANALYZER_DIR, "native")
    pe_sieve_exe = os.path.join(native_dir, "pe-sieve64.exe")
    # 兼容旧名称
    if not os.path.isfile(pe_sieve_exe):
        pe_sieve_exe_alt = os.path.join(native_dir, "pe-sieve.exe")
        if os.path.isfile(pe_sieve_exe_alt):
            pe_sieve_exe = pe_sieve_exe_alt
    pe_sieve_src = os.path.join(os.path.dirname(_ANALYZER_DIR), "..", "pe-sieve-master", "pe-sieve-master")
    result["pe_sieve"] = {"available": os.path.isfile(pe_sieve_exe), "type": "内存扫描",
                          "desc": "进程内存扫描/Hollowing检测",
                          "source": pe_sieve_src if os.path.isdir(pe_sieve_src) else None,
                          "note": "需编译 C++ 项目或将 pe-sieve.exe 放入 engine/native/"}
    
    # ClamAV
    import shutil
    clamscan_exe = os.path.join(native_dir, "clamscan.exe")
    clam_src = os.path.join(os.path.dirname(_ANALYZER_DIR), "..", "clamav-main", "clamav-main")
    if not os.path.isfile(clamscan_exe):
        found = shutil.which("clamscan")
        if found:
            clamscan_exe = found
    result["clamav"] = {"available": os.path.isfile(clamscan_exe), "type": "多引擎查杀",
                        "desc": "ClamAV 开源杀毒引擎",
                        "source": clam_src if os.path.isdir(clam_src) else None,
                        "note": "下载 ClamAV 或放入 engine/native/clamscan.exe"}
    
    # libpeconv
    libpe_src = os.path.join(os.path.dirname(_ANALYZER_DIR), "..", "libpeconv-master", "libpeconv-master")
    result["libpeconv"] = {"available": os.path.isdir(libpe_src) if libpe_src else False,
                           "type": "PE分析库", "desc": "PE 文件格式解析库（C++）",
                           "source": libpe_src if os.path.isdir(libpe_src) else None,
                           "note": "C++ 库，需编译为 DLL 后供 Python 调用"}
    
    # capa-master 本地源码
    capa_src = os.path.join(os.path.dirname(_ANALYZER_DIR), "..", "capa-master", "capa-master")
    result["capa_source"] = {"available": os.path.isdir(capa_src) if capa_src else False,
                             "type": "行为分析(源码)", "desc": "capa 本地源码",
                             "source": capa_src if os.path.isdir(capa_src) else None}

    # 天体引擎（沙箱行为分析）—— 子进程调用 tianti.exe，默认仅静态、不执行样本
    try:
        from engine.tianti_bridge import status as _tianti_status
        result["tianti"] = _tianti_status()
    except Exception as exc:                      # noqa: BLE001 - 状态查询不抛
        result["tianti"] = {"available": False, "type": "沙箱行为分析",
                            "desc": "天体引擎 TianTi", "error": str(exc)}

    return result


# ===================== 1. capa 行为分析 =====================

def _capa_rules_dir():
    """定位 capa 规则目录。

    ⚠️ pip 装的 capa wheel **不带 rules/**（规则在独立的 mandiant/capa-rules
    仓库里），所以规则必须由项目自带。解压后常多一层目录名，两种都认。
    """
    base = os.path.join(_ANALYZER_DIR, "capa_rules")
    for cand in (base,
                 os.path.join(base, "capa-rules-master"),
                 os.path.join(base, "capa-rules-9.4.0")):
        if not os.path.isdir(cand):
            continue
        for _root, _dirs, _files in os.walk(cand):
            if any(f.endswith((".yml", ".yaml")) for f in _files):
                return cand
    try:
        from capa.main import get_default_root
        d = os.path.join(str(get_default_root()), "rules")
        if os.path.isdir(d):
            return d
    except Exception:
        pass
    return None


def capa_analyze(file_path: str) -> dict:
    """
    使用 capa 分析 PE 文件的能力（ATT&CK 映射）
    依赖: pip install flare-capa
    """
    try:
        import capa.main
        import capa.rules
        import capa.engine
        import capa.loader

        from pathlib import Path as _P
        _rd = _capa_rules_dir()
        if not _rd:
            return {"status": "unavailable",
                    "error": "找不到 capa 规则目录（capa wheel 不带 rules/，"
                             "需下载 mandiant/capa-rules 放到 engine/capa_rules/）",
                    "file": file_path}
        rules = capa.rules.get_rules([_P(_rd)])
        try:
            _sig = capa.main.get_signatures()
        except Exception:
            _sig = []
        extractor = capa.loader.get_extractor(
            _P(file_path), "auto", "auto", "vivisect", _sig, disable_progress=True)
        
        import capa.capabilities.common as _cc
        capabilities = _cc.find_capabilities(rules, extractor, disable_progress=True)
        
        meta = {}   # collect_metadata 在 capa 9.x 签名已变，这里不再调用
        
        result = {
            "file": file_path,
            "attck": [],
            "mBC": [],
            "capabilities": {},
        }
        
        # meta 不再使用（capa 9.x 的 collect_metadata 签名已变）
        
        # capa 9.x 的 find_capabilities 返回 Capabilities **dataclass**
        # （字段 matches / feature_counts / library_functions），不是 dict —— 内容在 .matches
        for name, capa_matches in capabilities.matches.items():
            try:
                rule = rules[name]      # capa 9.x 的 RuleSet 只有 __getitem__，没有 .get()
            except Exception:
                continue
            ns = rule.meta.get("namespace", "")
            for addr, _ in capa_matches:
                cap_dict = {
                    "name": name,
                    "namespace": ns,
                    "description": rule.meta.get("description", ""),
                    "attck": [a for a in rule.meta.get("att&ck", [])],
                    "mbc": [m for m in rule.meta.get("mbc", [])],
                }
                if ns in ("load-code", "host-interaction", "communication", "data-manipulation",
                          "defense-evasion", "collection", "execution"):
                    result["capabilities"].setdefault(ns, []).append(cap_dict)
                for a in cap_dict["attck"]:
                    if a not in result["attck"]:
                        result["attck"].append(a)
                for m in cap_dict["mbc"]:
                    if m not in result["mBC"]:
                        result["mBC"].append(m)
        
        result["capability_count"] = sum(len(v) for v in result["capabilities"].values())
        result["status"] = "success"
        result["engine"] = "capa"
        return result
        
    except ImportError:
        return {"status": "unavailable", "error": "capa 未安装: pip install flare-capa", "file": file_path}
    except Exception as e:
        return {"status": "error", "error": str(e), "file": file_path}


# ===================== 2. yarGen 规则生成 =====================

def yargen_generate(sample_dir: str, output_dir: str = None, exclude_good: bool = True) -> dict:
    """
    使用 yarGen 从样本目录自动生成 YARA 规则
    """
    yargen_path = os.path.join(_ANALYZER_DIR, "yarGen.py")
    
    if not os.path.isfile(yargen_path):
        return {"status": "unavailable", "error": "yarGen.py 未找到"}
    
    if not os.path.isdir(sample_dir):
        return {"status": "error", "error": f"样本目录不存在: {sample_dir}"}
    
    if output_dir is None:
        output_dir = os.path.join(_ANALYZER_DIR, "generated_rules")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        cmd = [sys.executable, yargen_path, "-m", sample_dir, "-o", output_dir]
        if exclude_good:
            cmd.append("--excludegood")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # 统计生成结果
        rule_files = []
        if os.path.isdir(output_dir):
            for f in os.listdir(output_dir):
                if f.endswith(".yar") or f.endswith(".yara"):
                    rule_files.append(f)
        
        return {
            "status": "success",
            "engine": "yarGen",
            "sample_dir": sample_dir,
            "output_dir": output_dir,
            "rules_generated": len(rule_files),
            "rule_files": rule_files,
            "stdout": result.stdout[:2000] if result.stdout else "",
            "stderr": result.stderr[:500] if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "规则生成超时（5分钟）"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ===================== 3. PE-sieve 内存扫描 =====================

def pe_sieve_scan(pid: int = None, exe_path: str = None) -> dict:
    """
    使用 PE-sieve 扫描进程内存
    依赖: PE-sieve.exe 需放置在 engine/native/pe-sieve.exe
    """
    native_dir = os.path.join(_ANALYZER_DIR, "native")
    pe_sieve_exe = os.path.join(native_dir, "pe-sieve64.exe")
    if not os.path.isfile(pe_sieve_exe):
        pe_sieve_exe = os.path.join(native_dir, "pe-sieve.exe")
    
    if not os.path.isfile(pe_sieve_exe):
        return {
            "status": "unavailable",
            "error": "PE-sieve 未编译。下载: https://github.com/hasherezade/pe-sieve/releases",
            "note": "将 pe-sieve.exe 放入 engine/native/ 目录即可启用内存扫描"
        }
    
    try:
        cmd = [pe_sieve_exe, "/quiet", "/json"]
        if pid:
            cmd.extend(["/pid", str(pid)])
        elif exe_path:
            cmd.extend(["/pid", str(_get_pid_by_name(exe_path))])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"status": "success", "raw_output": result.stdout[:1000]}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "扫描超时"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _get_pid_by_name(name: str) -> int:
    """根据进程名查找 PID"""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.replace('"', '').split(",")
            if len(parts) >= 2:
                return int(parts[1].strip())
    except Exception:
        pass
    return 0


# ===================== 4. ClamAV 扫描 =====================

def clamav_scan(file_path: str) -> dict:
    """
    使用 ClamAV 扫描文件
    依赖: clamscan.exe 需在 PATH 中或 engine/native/clamscan.exe
    """
    native_dir = os.path.join(_ANALYZER_DIR, "native")
    clamscan_exe = os.path.join(native_dir, "clamscan.exe")
    
    import shutil
    if not os.path.isfile(clamscan_exe):
        found = shutil.which("clamscan")
        if found:
            clamscan_exe = found
    
    if not os.path.isfile(clamscan_exe):
        return {
            "status": "unavailable",
            "error": "ClamAV 未安装。下载: https://www.clamav.net/downloads",
            "note": "安装后将自动检测 clamscan.exe"
        }
    
    try:
        result = subprocess.run(
            [clamscan_exe, "--no-summary", file_path],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout.strip()
        
        infected = "FOUND" in output or result.returncode == 1
        return {
            "status": "success",
            "engine": "ClamAV",
            "file": file_path,
            "infected": infected,
            "output": output[:500],
            "return_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "扫描超时"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ===================== 5. libpeconv PE 分析 =====================

def libpeconv_info() -> dict:
    """返回 libpeconv 源码信息和集成状态"""
    libpe_src = os.path.join(os.path.dirname(_ANALYZER_DIR), "..", "libpeconv-master", "libpeconv-master")
    
    info = {
        "name": "libpeconv",
        "type": "PE 文件格式解析库",
        "language": "C++",
        "status": "source_only",
        "functions": [
            "peconv::load_pe_executable - 加载PE到内存",
            "peconv::unmap_pe - 转储内存中的PE",
            "peconv::get_nt_headers - 获取NT头",
            "peconv::is_pe - PE文件检测",
            "peconv::get_sections - 获取节表",
            "peconv::hook_pe - PE hook操作",
        ],
        "integration": "需编译为DLL后使用ctypes调用",
        "compile_cmd": "cmake -B build && cmake --build build --config Release",
    }
    
    if os.path.isdir(libpe_src):
        info["source_available"] = True
        info["source_path"] = libpe_src
        # 统计源文件
        h_files = [f for f in os.listdir(libpe_src) if f.endswith(".h")]
        cpp_files = [f for f in os.listdir(libpe_src) if f.endswith(".cpp")]
        info["header_count"] = len(h_files)
        info["source_count"] = len(cpp_files)
    else:
        info["source_available"] = False
    
    return info


# ===================== 6. 洞渊综合分析 =====================

def deep_scan(file_path: str, engines: list = None) -> dict:
    """
    洞渊综合分析 - 串联所有可用引擎
    engines: ["capa", "clamav", "yara"]
    """
    _STATUS["scanning"] = True
    _STATUS["current_file"] = file_path
    _STATUS["result"] = None
    
    if engines is None:
        engines = ["capa", "clamav"]
    
    results = {}
    
    if "capa" in engines:
        results["capa"] = capa_analyze(file_path)
    
    if "clamav" in engines:
        results["clamav"] = clamav_scan(file_path)
    
    if "yara" in engines:
        results["yara"] = yara_scan_file(file_path)

    # 天体引擎（沙箱行为分析）。默认不执行样本，只做静态；
    # 要跑沙箱须显式把 "tianti_sandbox" 放进 engines（仍受桥接层安全约束）。
    if "tianti" in engines or "tianti_sandbox" in engines:
        results["tianti"] = tianti_analyze(
            file_path, allow_execute=("tianti_sandbox" in engines))
    
    # 汇总威胁
    threats = []
    if results.get("capa", {}).get("status") == "success":
        capa_r = results["capa"]
        threats.append({
            "engine": "capa",
            "attck_count": len(capa_r.get("attck", [])),
            "capability_count": capa_r.get("capability_count", 0)
        })
    
    if results.get("clamav", {}).get("infected"):
        threats.append({
            "engine": "ClamAV",
            "output": results["clamav"].get("output", "")
        })
    
    if results.get("yara", {}).get("matches"):
        yr = results["yara"]
        threats.append({
            "engine": "YARA",
            "match_count": len(yr.get("matches", [])),
            "matches": yr["matches"]
        })

    # 天体引擎：只有 suspicious/malicious 才计入威胁
    ti = results.get("tianti") or {}
    if ti.get("status") == "success" and ti.get("verdict") in ("suspicious", "malicious"):
        threats.append({
            "engine": "tianti",
            "verdict": ti.get("verdict"),
            "score": ti.get("score"),
            "confidence": ti.get("confidence"),
            "executed": ti.get("executed"),          # False = 仅静态，证据强度要相应打折
            "detectors": [d.get("name") for d in (ti.get("detectors") or [])][:5],
            "tactics": ti.get("tactics"),
        })
    
    _STATUS["scanning"] = False
    _STATUS["result"] = {
        "file": file_path,
        "engines_used": list(results.keys()),
        "threats_found": len(threats),
        "threats": threats,
        "details": results
    }
    
    return _STATUS["result"]


def yara_scan_file(file_path: str) -> dict:
    """使用 YARA 规则扫描文件"""
    try:
        from engine.yara_scanner import YaraScanner
        scanner = YaraScanner()
        rules_dir = os.path.join(_ANALYZER_DIR, "yara_rules")
        scanner.load_rules(rules_dir)
        matches = scanner.scan_file(file_path)
        return {"status": "success", "engine": "YARA", "matches": matches, "match_count": len(matches)}
    except ImportError:
        return {"status": "unavailable", "error": "YARA 扫描模块不可用"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def tianti_analyze(file_path: str, allow_execute: bool = False,
                   policy: str = "deep") -> dict:
    """天体引擎沙箱行为分析（走 tianti.exe 子进程）。

    ⚠️ **安全边界**：`allow_execute=False`（默认）时只做静态分析、**不执行样本**。
    置 True 才会进天体的 containment 沙箱实际运行 —— 那是「受限执行」
    （受限令牌 + 低完整性 + Job + 防火墙 + 超时强杀），**不是 VM 隔离**，
    只适合用户主动发起、自己可控的样本。

    返回结构见 engine/tianti_bridge.py 的 analyze()。
    """
    try:
        from engine.tianti_bridge import analyze
        return analyze(file_path, allow_execute=allow_execute, policy=policy)
    except Exception as e:                        # noqa: BLE001 - 桥接层不抛
        return {"status": "error", "engine": "tianti", "error": str(e)}


def deep_scan_async(file_path: str, engines: list = None):
    """异步深度分析"""
    t = threading.Thread(target=lambda: deep_scan(file_path, engines), daemon=True)
    t.start()
    return {"status": "started", "file": file_path}
