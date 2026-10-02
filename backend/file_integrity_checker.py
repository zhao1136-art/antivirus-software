#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件完整性检测工具 (File Integrity Checker)
==========================================

功能：
  1. 生成指定文件/目录的哈希值（支持 MD5 / SHA-1 / SHA-256）
  2. 将哈希值保存到校验文件（格式与 md5sum 兼容，可按哈希值比对还原）
  3. 通过比对哈希值验证文件是否被篡改
  4. 批量检测（递归遍历目录）并生成检测报告（文本 / HTML）

用法示例：
  # 计算单个文件的哈希值
  python file_integrity_checker.py hash -a sha256 D:\\data\\app.exe

  # 批量生成目录校验文件（递归，排除日志与临时文件）
  python file_integrity_checker.py gen -a sha256 -r -e "*.log" -e "*.tmp" -o checksums.sha256 D:\\data

  # 使用校验文件验证完整性，并生成 HTML 检测报告
  python file_integrity_checker.py verify -c checksums.sha256 --report report.html

退出码：
  0  操作成功 / 校验全部通过
  1  检测到篡改、缺失、新增或无法读取的文件
  2  参数或使用错误
"""
import argparse
import fnmatch
import hashlib
import html as html_mod
import os
import re
import sys
from datetime import datetime

ALGORITHMS = ("md5", "sha1", "sha256")
CHUNK_SIZE = 1024 * 1024  # 1MB
_ALGO_HEX_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
_LINE_RE = re.compile(r"^([0-9a-fA-F]+)\s+(.+)$")

EXAMPLES = """
常用示例：
  %(prog)s hash -a md5 setup.exe
  %(prog)s gen -a sha256 -r -e "*.log" -o checksums.sha256 C:\\data
  %(prog)s verify -c checksums.sha256 --report report.html
"""


# --------------------------------------------------------------------------- #
# 核心哈希计算
# --------------------------------------------------------------------------- #
def compute_hash(path: str, algorithm: str) -> str:
    """分块计算文件哈希，返回十六进制摘要。"""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# 文件收集
# --------------------------------------------------------------------------- #
def _is_excluded(rel_path: str, patterns: list) -> bool:
    """判断相对路径是否命中排除规则（支持通配符）。"""
    rel = rel_path.replace("\\", "/")
    base = os.path.basename(rel)
    for pat in patterns:
        p = pat.replace("\\", "/")
        if fnmatch.fnmatch(base, p) or fnmatch.fnmatch(rel, p):
            return True
    return False


def collect_files(roots: list, recursive: bool, exclude_patterns: list):
    """收集待处理的文件列表。

    返回 (files, errors)：
      files: [(绝对路径, 相对路径), ...]，已去重并按相对路径排序
      errors: [错误消息, ...]
    """
    files = []
    errors = []
    seen = set()

    for r in roots:
        rp = os.path.abspath(r)
        if not os.path.exists(rp):
            errors.append(f"路径不存在: {r}")
            continue
        if os.path.isfile(rp):
            if rp not in seen:
                seen.add(rp)
                files.append((rp, os.path.basename(rp)))
            continue

        def _onerror(err):
            errors.append(f"无法访问目录 {err.filename}: {err.strerror or err}")

        for root, dirs, names in os.walk(rp, onerror=_onerror):
            if not recursive:
                dirs[:] = []
            for name in names:
                fp = os.path.join(root, name)
                rel = os.path.relpath(fp, rp)
                if exclude_patterns and _is_excluded(rel, exclude_patterns):
                    continue
                if fp not in seen:
                    seen.add(fp)
                    files.append((fp, rel.replace("\\", "/")))

    files.sort(key=lambda x: x[1].lower())
    return files, errors


# --------------------------------------------------------------------------- #
# 校验文件读写
# --------------------------------------------------------------------------- #
def load_checksum(path: str, default_algo: str):
    """读取校验文件，返回 (算法, {相对路径: 摘要}, [解析警告])。

    兼容标准 md5sum 输出格式（每行: <摘要>  <路径>），
    也支持本工具生成的带 # Algorithm: 头部的格式。
    """
    algo = default_algo
    entries = {}
    warnings = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    if line.lower().startswith("# algorithm:"):
                        a = line.split(":", 1)[1].strip().lower()
                        if a in ALGORITHMS:
                            algo = a
                    continue
                m = _LINE_RE.match(line)
                if not m:
                    warnings.append(f"第 {lineno} 行格式无效，已忽略: {line[:60]}")
                    continue
                digest, rel = m.group(1).lower(), m.group(2).strip()
                if len(digest) != _ALGO_HEX_LEN[algo]:
                    warnings.append(f"第 {lineno} 行摘要长度与算法 {algo} 不符，已忽略: {rel}")
                    continue
                entries[rel] = digest
    except OSError as e:
        print(f"[错误] 无法读取校验文件 {path}: {e}", file=sys.stderr)
        sys.exit(2)
    return algo, entries, warnings


def write_checksum(output: str, algorithm: str, entries: list) -> None:
    """写入校验文件，entries 为 [(相对路径, 摘要), ...]。"""
    lines = [
        "# File integrity checksum",
        f"# Algorithm: {algorithm}",
        f"# Generated by: file_integrity_checker",
        f"# Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Files: {len(entries)}",
        "",
    ]
    lines += [f"{digest}  {rel}" for rel, digest in entries]
    with open(output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
# 验证逻辑
# --------------------------------------------------------------------------- #
def verify_checksum(checksum_file: str, base_dir: str, default_algo: str) -> dict:
    """执行完整性验证，返回包含结果明细的字典。"""
    algo, expected, warnings = load_checksum(checksum_file, default_algo)
    results = []  # {rel, status, expected, actual, note}
    bad_count = 0

    for rel, digest in expected.items():
        full = os.path.normpath(os.path.join(base_dir, rel.replace("/", os.sep)))
        if not os.path.exists(full):
            results.append({"rel": rel, "status": "missing", "expected": digest, "actual": "", "note": ""})
            bad_count += 1
            continue
        if not os.path.isfile(full):
            results.append({"rel": rel, "status": "missing", "expected": digest, "actual": "", "note": "已变为目录"})
            bad_count += 1
            continue
        try:
            actual = compute_hash(full, algo)
        except (OSError, PermissionError) as e:
            results.append({"rel": rel, "status": "unreadable", "expected": digest, "actual": "", "note": str(e)})
            bad_count += 1
            continue
        if actual == digest:
            results.append({"rel": rel, "status": "ok", "expected": digest, "actual": actual, "note": ""})
        else:
            results.append({"rel": rel, "status": "modified", "expected": digest, "actual": actual, "note": ""})
            bad_count += 1

    # 检测“新增文件”：校验文件之外的、根目录下存在的文件
    # （校验文件自身位于扫描目录内时不计为新增）
    checksum_abs = os.path.abspath(checksum_file)
    new_files = []
    if os.path.isdir(base_dir):
        for root, dirs, names in os.walk(base_dir):
            for name in names:
                fp = os.path.join(root, name)
                if os.path.abspath(fp) == checksum_abs:
                    continue
                rel = os.path.relpath(fp, base_dir).replace("\\", "/")
                if rel not in expected:
                    new_files.append(rel)

    return {
        "algorithm": algo,
        "checksum_file": os.path.abspath(checksum_file),
        "base_dir": os.path.abspath(base_dir),
        "results": results,
        "new_files": sorted(new_files),
        "warnings": warnings,
        "summary": {
            "total": len(expected),
            "ok": sum(1 for r in results if r["status"] == "ok"),
            "modified": sum(1 for r in results if r["status"] == "modified"),
            "missing": sum(1 for r in results if r["status"] == "missing"),
            "unreadable": sum(1 for r in results if r["status"] == "unreadable"),
            "new": len(new_files),
        },
        "bad_count": bad_count + len(new_files),
    }


# --------------------------------------------------------------------------- #
# 报告输出
# --------------------------------------------------------------------------- #
def _conclusion(summary: dict, bad_count: int) -> str:
    if bad_count == 0:
        return "完整性校验通过：所有文件均与校验文件一致，未发现异常。"
    parts = []
    if summary["modified"]:
        parts.append(f"篡改 {summary['modified']} 个")
    if summary["missing"]:
        parts.append(f"缺失 {summary['missing']} 个")
    if summary["unreadable"]:
        parts.append(f"无法读取 {summary['unreadable']} 个")
    if summary["new"]:
        parts.append(f"新增 {summary['new']} 个")
    return f"完整性校验未通过：发现 {', '.join(parts)}，文件可能已被篡改。"


def format_text_report(data: dict) -> str:
    s = data["summary"]
    lines = [
        "=" * 52,
        " 文件完整性检测报告",
        "=" * 52,
        f"生成时间  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"校验文件  : {data['checksum_file']}",
        f"验证根路径: {data['base_dir']}",
        f"哈希算法  : {data['algorithm']}",
        "",
        "[结果统计]",
        f"  总条目: {s['total']}   通过: {s['ok']}   篡改: {s['modified']}   缺失: {s['missing']}   新增: {s['new']}   无法读取: {s['unreadable']}",
    ]
    abnormal = [r for r in data["results"] if r["status"] != "ok"]
    if abnormal or data["new_files"]:
        lines += ["", "[异常明细]"]
        for r in abnormal:
            if r["status"] == "modified":
                lines.append(f"  [篡改]  {r['rel']}")
                lines.append(f"           期望 {r['expected']}")
                lines.append(f"           实际 {r['actual']}")
            elif r["status"] == "missing":
                lines.append(f"  [缺失]  {r['rel']}" + (f"（{r['note']}）" if r["note"] else ""))
            else:
                lines.append(f"  [读取失败]  {r['rel']}（{r['note']}）")
        for rel in data["new_files"]:
            lines.append(f"  [新增]  {rel}")
    lines += [
        "",
        "[结论]",
        f"  {_conclusion(s, data['bad_count'])}",
    ]
    if data["warnings"]:
        lines += ["", "[解析警告]"]
        lines += [f"  {w}" for w in data["warnings"]]
    return "\n".join(lines)


_HTML_CSS = """
body{font-family:"Microsoft YaHei",Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f9;color:#333}
.wrap{max-width:960px;margin:24px auto;padding:0 16px}
h1{font-size:22px;margin:8px 0 4px}
.meta{color:#777;font-size:13px;margin-bottom:16px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.card{flex:1;min-width:120px;background:#fff;border-radius:8px;padding:14px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card .num{font-size:26px;font-weight:700}
.card .lbl{font-size:12px;color:#777}
.ok .num{color:#2e9e5b}.bad .num{color:#d64545}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
th,td{padding:8px 12px;text-align:left;font-size:13px;border-bottom:1px solid #eef0f3}
th{background:#2f3a4c;color:#fff}
tr.ok td{color:#555}
tr.modified td,tr.missing td,tr.unreadable td{background:#fff3f3}
tr.new td{background:#fff9e8}
.tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px}
.tag.ok{background:#e3f5ea;color:#2e9e5b}.tag.modified,.tag.missing,.tag.unreadable{background:#fde3e3;color:#d64545}
.tag.new{background:#fdf3d0;color:#b8860b}
.hash{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:#888}
.conclusion{margin-top:16px;padding:14px;border-radius:8px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.conclusion.pass{border-left:4px solid #2e9e5b}
.conclusion.fail{border-left:4px solid #d64545}
.footer{color:#aaa;font-size:12px;text-align:center;margin:20px 0}
"""


def format_html_report(data: dict) -> str:
    s = data["summary"]
    rows = []
    for r in data["results"]:
        if r["status"] == "ok":
            tag, cls = "通过", "ok"
            cell = '<span class="tag ok">通过</span>'
        elif r["status"] == "modified":
            tag, cls = "篡改", "modified"
            cell = '<span class="tag modified">篡改</span>'
        elif r["status"] == "missing":
            tag, cls = "缺失", "missing"
            cell = '<span class="tag missing">缺失</span>'
        else:
            tag, cls = "读取失败", "unreadable"
            cell = '<span class="tag unreadable">读取失败</span>'
        detail = r["note"] or (f'<div class="hash">期望 {r["expected"]}</div><div class="hash">实际 {r["actual"]}</div>'
                                if r["status"] == "modified" else "")
        rows.append(
            f'<tr class="{cls}"><td>{cell}</td><td>{html_mod.escape(r["rel"])}</td>'
            f'<td class="hash">{html_mod.escape(r["expected"])}</td><td>{detail}</td></tr>'
        )
    for rel in data["new_files"]:
        rows.append(f'<tr class="new"><td><span class="tag new">新增</span></td>'
                    f'<td>{html_mod.escape(rel)}</td><td class="hash">-</td><td>校验文件中不存在</td></tr>')

    passed = data["bad_count"] == 0
    conclusion_cls = "pass" if passed else "fail"
    table = (f'<table><tr><th>状态</th><th>文件</th><th>期望摘要</th><th>说明</th></tr>'
             + "".join(rows) + "</table>") if rows else "<p>校验文件中没有记录任何文件。</p>"

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>文件完整性检测报告</title><style>{_HTML_CSS}</style></head>
<body><div class="wrap">
<h1>文件完整性检测报告</h1>
<div class="meta">生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}　|　校验文件：{html_mod.escape(data['checksum_file'])}　|　根路径：{html_mod.escape(data['base_dir'])}　|　算法：{data['algorithm'].upper()}</div>
<div class="cards">
<div class="card"><div class="num">{s['total']}</div><div class="lbl">总条目</div></div>
<div class="card ok"><div class="num">{s['ok']}</div><div class="lbl">通过</div></div>
<div class="card bad"><div class="num">{s['modified']}</div><div class="lbl">篡改</div></div>
<div class="card bad"><div class="num">{s['missing']}</div><div class="lbl">缺失</div></div>
<div class="card"><div class="num">{s['new']}</div><div class="lbl">新增</div></div>
<div class="card bad"><div class="num">{s['unreadable']}</div><div class="lbl">无法读取</div></div>
</div>
{table}
<div class="conclusion {conclusion_cls}"><b>结论：</b>{html_mod.escape(_conclusion(s, data['bad_count']))}</div>
<div class="footer">由 file_integrity_checker 生成</div>
</div></body></html>"""


# --------------------------------------------------------------------------- #
# 控制台输出
# --------------------------------------------------------------------------- #
def _progress(done: int, total: int) -> None:
    if total <= 1:
        return
    sys.stderr.write(f"\r正在处理 {done}/{total} 个文件...")
    if done == total:
        sys.stderr.write("\n")
    sys.stderr.flush()


def print_verify_console(data: dict) -> None:
    s = data["summary"]
    print(f"[验证信息] 校验文件: {data['checksum_file']}")
    print(f"[验证信息] 验证根路径: {data['base_dir']}")
    print(f"[验证信息] 哈希算法: {data['algorithm'].upper()}")
    print(f"[验证信息] 统计: 总数 {s['total']} | 通过 {s['ok']} | 篡改 {s['modified']} | "
          f"缺失 {s['missing']} | 新增 {s['new']} | 无法读取 {s['unreadable']}")
    for r in data["results"]:
        if r["status"] == "modified":
            print(f"[篡改] {r['rel']}")
            print(f"        期望 {r['expected']}")
            print(f"        实际 {r['actual']}")
        elif r["status"] == "missing":
            print(f"[缺失] {r['rel']}" + (f"（{r['note']}）" if r["note"] else ""))
        elif r["status"] == "unreadable":
            print(f"[读取失败] {r['rel']}（{r['note']}）")
    for rel in data["new_files"]:
        print(f"[新增] {rel}")
    for w in data["warnings"]:
        print(f"[警告] {w}", file=sys.stderr)
    print(f"[结论] {_conclusion(s, data['bad_count'])}")


# --------------------------------------------------------------------------- #
# 子命令
# --------------------------------------------------------------------------- #
def cmd_hash(args: argparse.Namespace) -> None:
    files, errors = collect_files(args.paths, args.recursive, args.exclude)
    for e in errors:
        print(f"[警告] {e}", file=sys.stderr)
    if not files:
        print("[错误] 未找到可处理的文件。", file=sys.stderr)
        sys.exit(2)
    algo = args.algorithm
    failed = 0
    for i, (abs_path, rel) in enumerate(files, 1):
        try:
            digest = compute_hash(abs_path, algo)
            print(f"{digest}  {rel}")
        except (OSError, PermissionError) as e:
            failed += 1
            print(f"[错误] 无法读取 {rel}: {e}", file=sys.stderr)
        _progress(i, len(files))
    if failed:
        sys.exit(1)


def cmd_gen(args: argparse.Namespace) -> None:
    files, errors = collect_files(args.paths, args.recursive, args.exclude)
    for e in errors:
        print(f"[警告] {e}", file=sys.stderr)
    if not files:
        print("[错误] 未找到可处理的文件。", file=sys.stderr)
        sys.exit(2)

    algo = args.algorithm
    entries = []
    failed = 0
    total = len(files)
    for i, (abs_path, rel) in enumerate(files, 1):
        try:
            digest = compute_hash(abs_path, algo)
            entries.append((rel, digest))
        except (OSError, PermissionError) as e:
            failed += 1
            print(f"[警告] 跳过 {rel}: {e}", file=sys.stderr)
        _progress(i, total)

    output = args.output or f"checksums.{algo}"
    write_checksum(output, algo, entries)
    print(f"[结果] 共处理 {total} 个文件，成功 {total - failed} 个，失败 {failed} 个。")
    print(f"[结果] 校验文件已保存至: {os.path.abspath(output)}")
    sys.exit(1 if failed else 0)


def cmd_verify(args: argparse.Namespace) -> None:
    checksum_file = args.checksum
    if not os.path.isfile(checksum_file):
        print(f"[错误] 校验文件不存在: {checksum_file}", file=sys.stderr)
        sys.exit(2)
    base_dir = os.path.abspath(args.path) if args.path else os.path.abspath(os.path.dirname(checksum_file) or ".")
    if not os.path.exists(base_dir):
        print(f"[错误] 验证根路径不存在: {base_dir}", file=sys.stderr)
        sys.exit(2)

    data = verify_checksum(checksum_file, base_dir, args.algorithm)
    print_verify_console(data)

    if args.report:
        try:
            if args.report.lower().endswith(".html"):
                content = format_html_report(data)
            else:
                content = format_text_report(data)
            with open(args.report, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[结果] 检测报告已保存至: {os.path.abspath(args.report)}")
        except OSError as e:
            print(f"[错误] 无法写入报告 {args.report}: {e}", file=sys.stderr)

    sys.exit(1 if data["bad_count"] else 0)


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="file_integrity_checker",
        description="文件完整性检测工具：生成/保存/校验文件哈希，支持批量检测并输出检测报告。",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # 公共参数通过父解析器提供给每个子命令，便于“子命令之后”使用
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-a", "--algorithm", choices=ALGORITHMS, default="sha256",
                        help="哈希算法，可选 %s，默认 sha256" % " / ".join(ALGORITHMS))
    common.add_argument("-r", "--recursive", action="store_true", help="递归处理子目录")
    common.add_argument("-e", "--exclude", action="append", default=[], metavar="PATTERN",
                        help="排除匹配的文件（支持通配符，可重复指定，如 -e \"*.log\"）")

    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    h = sub.add_parser("hash", parents=[common], help="计算并输出文件/目录的哈希值")
    h.add_argument("paths", nargs="+", metavar="PATH", help="文件或目录路径")
    h.set_defaults(func=cmd_hash)

    g = sub.add_parser("gen", parents=[common], help="生成校验文件（保存哈希值）")
    g.add_argument("paths", nargs="+", metavar="PATH", help="文件或目录路径")
    g.add_argument("-o", "--output", metavar="FILE", help="校验文件输出路径（默认: checksums.<算法>）")
    g.set_defaults(func=cmd_gen)

    v = sub.add_parser("verify", parents=[common], help="使用校验文件验证文件完整性")
    v.add_argument("-c", "--checksum", required=True, metavar="FILE", help="校验文件路径")
    v.add_argument("-p", "--path", metavar="PATH", help="待验证的根路径（默认: 校验文件所在目录）")
    v.add_argument("--report", metavar="FILE", help="将检测报告写入文件（扩展名为 .html 生成网页报告，否则生成文本报告）")
    v.set_defaults(func=cmd_verify)
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
