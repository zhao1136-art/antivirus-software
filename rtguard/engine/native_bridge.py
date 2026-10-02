"""
安盾破军引擎 - Python 绑定层（子进程方式）（破军主杀伐，原生利刃）
通过调用 native_engine.exe 子进程执行高性能操作，无 CRT 兼容问题
"""

import os
import sys
import json
import subprocess

# ============== EXE 查找 ==============

def _find_exe():
    candidates = []
    base = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(base, "native", "native_engine.exe"))
    if getattr(sys, 'frozen', False):
        candidates.append(os.path.join(sys._MEIPASS, "engine", "native", "native_engine.exe"))
    
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


_EXE_PATH = _find_exe()


def _run(*args):
    """调用破军引擎 EXE，返回 JSON 解析结果"""
    if _EXE_PATH is None:
        return None
    try:
        result = subprocess.run(
            [_EXE_PATH] + list(args),
            capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout.strip())
        if result.stderr:
            print(f"[破军引擎] stderr: {result.stderr}")
        return None
    except subprocess.TimeoutExpired:
        print(f"[破军引擎] 超时: {' '.join(args)}")
        return None
    except json.JSONDecodeError as e:
        print(f"[破军引擎] JSON 解析失败: {e}")
        return None
    except Exception as e:
        print(f"[破军引擎] 调用失败: {e}")
        return None


# ============== Python 接口类 ==============

class NativeEngine:
    """御天破军引擎 Python 接口"""

    @staticmethod
    def available() -> bool:
        return _EXE_PATH is not None and os.path.isfile(_EXE_PATH)

    @staticmethod
    def version() -> dict:
        return _run("version")

    @staticmethod
    def self_test() -> dict:
        return _run("selftest")

    # ---- SHA256 ----

    @staticmethod
    def sha256_file(filepath: str) -> dict:
        return _run("sha256", filepath)

    @staticmethod
    def sha256_directory(dirpath: str, max_files: int = 500) -> list:
        """批量 SHA256（通过多次调用 EXE 实现）"""
        import glob as _glob
        results = []
        files = [os.path.join(dirpath, f) for f in os.listdir(dirpath) 
                 if os.path.isfile(os.path.join(dirpath, f))][:max_files]
        for fp in files:
            r = _run("sha256", fp)
            if r and "sha256" in r:
                results.append({"file": os.path.basename(fp), "sha256": r["sha256"], "size": r.get("size", 0)})
        return results

    # ---- PE 解析 ----

    @staticmethod
    def pe_parse_full(filepath: str) -> dict:
        return _run("peparse", filepath)

    @staticmethod
    def pe_quick_check(filepath: str) -> dict:
        r = _run("peparse", filepath)
        if r and r.get("valid_pe"):
            return {"is_pe": True, "type": r.get("pe_type", "PE32"), "machine": r.get("machine", 0), "sections": r.get("sections", 0)}
        return {"is_pe": False}

    # ---- 启发式检测 ----

    @staticmethod
    def heuristic_score(pe_json: dict) -> dict:
        """基于 PE 解析结果启发式打分"""
        rwx = pe_json.get("rwx_sections", 0)
        ent = pe_json.get("max_entropy", 0)
        apis = pe_json.get("high_risk_api_count", 0)
        sub = pe_json.get("subsystem", 0)
        sig = 1 if pe_json.get("has_signature", False) else 0
        urls = pe_json.get("suspicious_urls_count", 0)
        sz = pe_json.get("size_of_code", 0)
        return _run("heuristic", str(rwx), str(ent), str(apis), str(sub), str(sig), str(urls), str(sz))

    @staticmethod
    def heuristic_score_fast(rwx: int, entropy: float, apis: int,
                              subsystem: int, has_sig: int, urls: int, size_code: int) -> dict:
        return _run("heuristic", str(rwx), str(entropy), str(apis), str(subsystem), str(has_sig), str(urls), str(size_code))

    # ---- 系统巡检 ----

    @staticmethod
    def enum_processes() -> dict:
        return _run("processes")

    @staticmethod
    def scan_startup() -> dict:
        return _run("startup")

    @staticmethod
    def enum_network() -> dict:
        return _run("network")

    @staticmethod
    def sys_summary() -> dict:
        return _run("sysinfo")

    # ---- 隔离区 ----

    @staticmethod
    def quarantine_move(filepath: str, qdir: str) -> dict:
        return _run("qmove", filepath, qdir)

    @staticmethod
    def quarantine_restore(quar_path: str, restore_dir: str) -> dict:
        """恢复隔离文件（反向 XOR 即解密移动）"""
        return _run("qmove", quar_path, restore_dir)

    @staticmethod
    def quarantine_delete(quar_path: str) -> dict:
        """永久删除隔离文件"""
        try:
            os.remove(quar_path)
            return {"success": True}
        except OSError as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def quarantine_list(qdir: str) -> dict:
        return _run("qlist", qdir)


# ============== 单例 ==============
_engine = None

def get_native_engine() -> NativeEngine:
    global _engine
    if _engine is None:
        _engine = NativeEngine()
    return _engine
