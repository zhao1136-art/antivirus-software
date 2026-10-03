"""copy 后端：复制式隔离（第一个隔离引擎后端）。

思路
----
把样本运行需要的东西**复制**到沙箱目录，样本在副本上跑。
写落在副本里，真实文件根本不在它视野里。

沙箱布局（沿用 sandbox.py 既有约定，不改路径规则）：

    %TEMP%\\yutian_sandbox\\<task_id>\\        <- 沙箱根 = 子进程工作目录(lpCurrentDirectory)
        <sample_name>                          <- 样本副本（真正执行的，命令行传它）
        <同目录的 DLL / 配置 / 资源副本…>

样本原目录里"它可能需要的同目录文件"也一并复制（DLL/配置/资源），
总量上限 256 MB / 512 个文件，超了就把 truncated 标成 True（如实上报，不假装完整）。

必须诚实面对的本质限制
----------------------
样本内部引用的**绝对路径**（如 C:\\Windows\\System32\\kernel32.dll）**不会**
被重定向到副本 —— 用户态做不到，除非用 ProjFS 或内核驱动（minifilter）。
所以：
  * 能力表里 absolute_path_redirect = False，绝不假装支持；
  * 报告里写明：隔离的是"样本自身及其同目录文件"，不是整个文件系统。

换句话说：副本隔离挡住的是"样本在自己目录里搞破坏 / 篡改同目录文件"，
挡不住"样本去改 C:\\Windows"（那一层仍由 Low IL 令牌负责拒绝）。
"""
from __future__ import annotations

import os
import shutil
import threading

from .base import IsolationEngine, make_prepare_result, normalize_path

# ── 沙箱根目录名（与 sandbox.py 的 SANDBOX_ROOT_DIRNAME 保持一致）──
SANDBOX_ROOT_DIRNAME = "yutian_sandbox"

# ── 复制容量上限 ──
COPY_MAX_TOTAL_BYTES = 256 * 1024 * 1024      # 总量 256 MB
COPY_MAX_FILES = 512                          # 同目录文件个数上限
COPY_MAX_SINGLE_BYTES = 64 * 1024 * 1024      # 单个附属文件上限 64 MB（样本本身不受限）
COPY_MAX_SCAN_ENTRIES = 20000                 # 单目录最多扫描条目数（防病态目录）
COPY_MAX_SKIPPED_RECORDS = 20                 # 报告里最多列 20 条跳过记录
COPY_MAX_ERROR_RECORDS = 20                   # 报告里最多列 20 条复制失败记录

# 加载器依赖 / 配置资源 扩展名（用于排序：优先复制"样本真正需要"的）
_LOADER_EXTS = frozenset({
    ".dll", ".ocx", ".cpl", ".sys", ".drv", ".ax", ".tsp", ".pyd", ".winmd",
})
_DATA_EXTS = frozenset({
    ".config", ".ini", ".json", ".xml", ".dat", ".bin", ".resources",
    ".manifest", ".txt", ".csv", ".db", ".sqlite", ".mui", ".pak", ".idx",
    ".msi", ".cab", ".bmp", ".png", ".ico", ".jpg", ".jpeg", ".gif", ".cur",
    ".ttf", ".nls", ".cat", ".pdb",
})
# 永不复制的系统文件
_BLACKLIST_NAMES = frozenset({
    "pagefile.sys", "hiberfil.sys", "swapfile.sys", "memory.dmp",
    "desktop.ini", "thumbs.db",
})

# 跳过同目录批量复制的目录（样本目录正好是这些时）
_SKIP_SUBTREE_ENV = ("SystemRoot", "windir")
_SKIP_EXACT_ENV = (
    "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData",
    "CommonProgramFiles", "CommonProgramFiles(x86)",
)


def _format_size(size: float) -> str:
    """格式化字节数为可读字符串"""
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def same_dir_skip_reason(sample_dir: str) -> str:
    """判断样本目录是否应该跳过"同目录批量复制"

    系统目录（C:\\Windows 整棵树）里躺着几万个文件，把 System32 复制进沙箱
    既慢又毫无意义（那些 DLL 本来就能被 Low IL 进程读到），
    所以这里显式跳过，并把原因写进报告 —— 不静默跳过。
    """
    if not sample_dir:
        return ""
    d = normalize_path(sample_dir)
    for var in _SKIP_SUBTREE_ENV:
        root = os.environ.get(var)
        if not root:
            continue
        r = normalize_path(root)
        if d == r or d.startswith(r + os.sep):
            return (f"样本目录位于系统目录树下（{root}），跳过同目录批量复制："
                    "System32/WinSxS 下有数万个文件，复制它们既慢又无用"
                    "（只复制样本自身）")
    for var in _SKIP_EXACT_ENV:
        root = os.environ.get(var)
        if root and normalize_path(root) == d:
            return (f"样本目录就是程序/数据根目录（{root}），跳过同目录批量复制"
                    "（只复制样本自身）")
    return ""


def _candidate_rank(name: str, sample_stem: str) -> int:
    """复制优先级：0 同名词干 > 1 加载器依赖 > 2 配置资源 > 3 其它"""
    stem, ext = os.path.splitext(name)
    if stem.lower() == sample_stem:
        return 0
    ext = ext.lower()
    if ext in _LOADER_EXTS:
        return 1
    if ext in _DATA_EXTS:
        return 2
    return 3


def _sort_candidates(item: tuple) -> tuple:
    """排序：优先级 -> 体积小的先来 -> 名字（确定性，便于复现）"""
    name, size, rank = item
    return (rank, size, name.lower())


class CopyEngine(IsolationEngine):
    """复制式隔离引擎"""

    name = "copy"

    def __init__(self, requested_name: str | None = None,
                 fallback_reason: str = ""):
        super().__init__(requested_name, fallback_reason)
        self._root = ""
        self._work_dir = ""
        self._exec_path = ""
        self._mapping: dict[str, str] = {}
        self._prepared = False
        self._cleaned = False
        self._last_result: dict = {}
        self._lock = threading.Lock()

    # ── 能力申报（交付物核心）──

    def capabilities(self) -> dict:
        """复制式隔离的真实能力边界

        absolute_path_redirect 必须是 False：用户态改不了 C:\\ 的路径解析。
        有能力的分析员会据此判断"样本写 C:\\Windows 失败"是隔离还是 Low IL。
        """
        return {
            "file_copy": True,
            "absolute_path_redirect": False,
            "registry_redirect": False,
            "writable_sandbox": True,
            "coverage": "sample_and_its_directory",
            "limitation": "样本引用的绝对路径不会被重定向；真 CoW 需要内核驱动或 ProjFS",
            "copy_scope": "sample + same_directory_files(dll/config/resource)",
            "max_total_bytes": COPY_MAX_TOTAL_BYTES,
            "max_files": COPY_MAX_FILES,
            "max_single_file_bytes": COPY_MAX_SINGLE_BYTES,
            "truncated_capable": True,
        }

    def scope_note(self) -> str:
        return ("隔离作用范围 = 样本自身及其同目录文件（已复制到沙箱根，样本执行的"
                "是副本）；不是整个文件系统 —— 样本内部引用的绝对路径"
                "（如 C:\\Windows\\System32\\kernel32.dll）仍解析到真实路径，"
                "那部分只能靠 Low IL 令牌拒绝越权写。")

    def is_active(self) -> bool:
        return True

    # ── 路径 ──

    @staticmethod
    def sandbox_root_for(task_id: str) -> str:
        """沙箱根目录：%TEMP%\\yutian_sandbox\\<task_id>"""
        temp = os.environ.get("TEMP") or os.path.expanduser("~")
        return os.path.join(temp, SANDBOX_ROOT_DIRNAME, str(task_id))

    def map_path(self, real_path: str) -> str:
        """真实路径 -> 沙箱内副本路径

        只映射"本次真正复制过的文件"；其它路径原样返回 —— 因为本引擎
        **没有**绝对路径重定向能力（capabilities.absolute_path_redirect=False），
        假装映射过就是在骗分析员。
        """
        if not real_path:
            return real_path
        return self._mapping.get(normalize_path(real_path), real_path)

    def copied_map(self) -> dict:
        """本次复制映射表（真实路径 -> 副本路径）"""
        return dict(self._mapping)

    # ── prepare ──

    def prepare(self, sample_path: str, task_id: str) -> dict:
        """建立沙箱目录并复制样本 + 同目录文件

        失败时返回 ok=False（并**不**自行删目录：调用方降级前会调 cleanup()）。
        """
        with self._lock:
            if self._prepared and self._last_result:
                # 幂等：同一个引擎实例重复 prepare 直接返回既有结论（字段完整，
                # 不再是只有 exec_path/work_dir 的残缺结果）
                cached = dict(self._last_result)
                cached["notes"] = list(cached.get("notes") or []) + [
                    "引擎已 prepare 过，复用既有沙箱目录"
                ]
                return cached
            # 一次新的 prepare 生命周期开始（cleanup 之后允许再次 prepare）
            self._cleaned = False

            sample_path = os.path.abspath(sample_path)
            root = self.sandbox_root_for(task_id)
            self._root = root
            self._work_dir = root
            result = make_prepare_result(
                self.name, sample_path,
                root_dir=root, work_dir=root,
                capabilities=self.capabilities(),
            )

            if not os.path.isfile(sample_path):
                result["degraded_reason"] = "样本文件不存在，无法复制"
                return result

            sample_name = os.path.basename(sample_path)
            sample_dir = os.path.dirname(sample_path)
            original_size = 0
            try:
                original_size = os.path.getsize(sample_path)
            except OSError:
                pass

            try:
                os.makedirs(root, exist_ok=True)
            except Exception as e:
                result["degraded_reason"] = (
                    f"创建沙箱根目录失败: {type(e).__name__}: {e}")
                return result

            notes: list[str] = []
            dest_sample = os.path.join(root, sample_name)

            # 1. 复制样本本身（这一步失败 = 引擎不可用，必须降级）
            sample_is_copy = True
            if normalize_path(sample_dir) == normalize_path(root):
                # 样本本来就在沙箱根里（罕见），无须复制
                dest_sample = sample_path
                sample_is_copy = False
                notes.append("样本原本就位于沙箱根目录内，无需复制")
            else:
                try:
                    shutil.copy2(sample_path, dest_sample)
                except Exception as e:
                    result["degraded_reason"] = (
                        f"复制样本失败: {type(e).__name__}: {e}")
                    return result

            self._mapping[normalize_path(sample_path)] = dest_sample
            copied_bytes = 0
            try:
                copied_bytes = os.path.getsize(dest_sample)
            except OSError:
                pass
            if original_size and copied_bytes != original_size:
                notes.append(
                    f"样本副本大小({copied_bytes})与原始({original_size})不一致，"
                    "可能被安全软件拦截或改写")
            self._exec_path = dest_sample

            # 2. 同目录文件（DLL / 配置 / 资源）
            candidates, skip_reason = self._collect_same_dir_files(
                sample_dir, sample_name)
            if skip_reason:
                notes.append(skip_reason)

            copied_files = 0          # 同目录文件复制计数
            skipped: list[dict] = []
            errors: list[dict] = []
            over_quota = 0
            total_bytes = copied_bytes

            for name, size, rank in candidates:
                src = os.path.join(sample_dir, name)
                if copied_files >= COPY_MAX_FILES:
                    over_quota += 1
                    continue
                if rank > 0 and size > COPY_MAX_SINGLE_BYTES:
                    over_quota += 1
                    if len(skipped) < COPY_MAX_SKIPPED_RECORDS:
                        skipped.append({
                            "path": src,
                            "reason": (f"单文件 {_format_size(size)} 超过上限 "
                                       f"{_format_size(COPY_MAX_SINGLE_BYTES)}"),
                        })
                    continue
                if total_bytes + size > COPY_MAX_TOTAL_BYTES:
                    over_quota += 1
                    if len(skipped) < COPY_MAX_SKIPPED_RECORDS:
                        skipped.append({
                            "path": src,
                            "reason": (f"超出总量上限 {_format_size(COPY_MAX_TOTAL_BYTES)}"
                                       f"（当前已 {_format_size(total_bytes)}）"),
                        })
                    continue
                dst = os.path.join(root, name)
                try:
                    shutil.copy2(src, dst)
                except Exception as e:
                    if len(errors) < COPY_MAX_ERROR_RECORDS:
                        errors.append(
                            {"path": src, "error": f"{type(e).__name__}: {e}"})
                    continue
                copied_files += 1
                total_bytes += size
                self._mapping[normalize_path(src)] = dst

            truncated = over_quota > 0
            if skip_reason:
                notes.append("同目录复制范围被裁剪（见上）")
            if truncated:
                notes.append(
                    f"因容量上限未复制全部同目录文件：另有 {over_quota} 个文件被跳过"
                    "（truncated=true，不假装完整）")
            if errors:
                notes.append(f"{len(errors)} 个同目录文件复制失败（见 copy_errors）")

            notes.append(
                f"已复制同目录文件 {copied_files} 个（另加样本自身），"
                f"合计 {_format_size(total_bytes)}")
            notes.append(self.scope_note())

            self._prepared = True
            result.update({
                "ok": True,
                "exec_path": dest_sample,
                # copied_files = 沙箱内实际落地的文件总数（含样本自身）；
                # 同目录部分的计数另见 copied_files_in_dir
                "copied_files": copied_files + (1 if sample_is_copy else 0),
                "copied_files_in_dir": copied_files,
                "copied_bytes": total_bytes,
                "truncated": truncated,
                "skipped": skipped,
                "copy_errors": errors,
                "notes": notes,
                "degraded_reason": "",
            })
            self._last_result = dict(result)
            return result

    # ── 同目录候选 ──

    def _collect_same_dir_files(self, sample_dir: str,
                                sample_name: str) -> tuple[list, str]:
        """枚举样本同目录的普通文件（不跟随符号链接/重解析点）

        Returns:
            (候选列表 [(name, size, rank)], 跳过原因)
        """
        reason = same_dir_skip_reason(sample_dir)
        if reason:
            return [], reason

        root_norm = normalize_path(self._root)
        stem = os.path.splitext(sample_name)[0]
        out: list = []
        try:
            with os.scandir(sample_dir) as it:
                for idx, entry in enumerate(it):
                    if idx >= COPY_MAX_SCAN_ENTRIES:
                        out.sort(key=_sort_candidates)
                        return (out,
                                f"样本目录条目超过 {COPY_MAX_SCAN_ENTRIES} 个，"
                                f"只扫描了前 {COPY_MAX_SCAN_ENTRIES} 项")
                    try:
                        # follow_symlinks=False：跳过符号链接/junction，
                        # 避免把别处的文件（甚至整个盘）拖进沙箱
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    low = entry.name.lower()
                    if low == sample_name.lower() or low in _BLACKLIST_NAMES:
                        continue
                    src_norm = normalize_path(entry.path)
                    if src_norm == root_norm or src_norm.startswith(root_norm + os.sep):
                        continue
                    out.append((entry.name, int(st.st_size),
                                _candidate_rank(entry.name, stem)))
        except OSError as e:
            return [], f"枚举样本目录失败: {type(e).__name__}: {e}"
        out.sort(key=_sort_candidates)
        return out, ""

    # ── cleanup ──

    def _safe_to_remove(self, path: str) -> bool:
        """删除前校验：只允许删 %TEMP%\\yutian_sandbox\\<task_id> 形态的目录"""
        if not path:
            return False
        try:
            p = os.path.abspath(path)
            parent = os.path.dirname(p)
            if os.path.basename(parent).lower() != SANDBOX_ROOT_DIRNAME.lower():
                return False
            temp = os.environ.get("TEMP") or os.path.expanduser("~")
            return normalize_path(os.path.dirname(parent)) == normalize_path(temp)
        except Exception:
            return False

    def cleanup(self) -> None:
        """删除沙箱根目录（幂等；删除失败原因记在 cleanup_error）

        幂等语义：同一个实例连续调用两次不会报错，第二次直接返回（不会重试）。
        删除成功后实例回到"未 prepare"状态，允许再次 prepare（新生命周期）。
        """
        with self._lock:
            if self._cleaned:
                return
            self._cleaned = True
            root = self._root

        if not root or not os.path.isdir(root):
            self._cleanup_error = ""
            self._after_cleanup()
            return
        if not self._safe_to_remove(root):
            self._cleanup_error = f"拒绝删除非常规路径: {root}"
            return
        try:
            shutil.rmtree(root)
        except Exception as e:
            first = f"{type(e).__name__}: {e}"
            try:
                shutil.rmtree(root, ignore_errors=True)
            except Exception:
                pass
            if os.path.isdir(root):
                self._cleanup_error = first[:300]
                return
        self._cleanup_error = ""
        self._after_cleanup()

    def _after_cleanup(self):
        """清理成功后的状态复位（允许同一实例再次 prepare）"""
        with self._lock:
            self._prepared = False
            self._mapping.clear()
            self._last_result = {}
