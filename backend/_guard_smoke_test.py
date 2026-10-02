# -*- coding: utf-8 -*-
"""临时测试：御天卫士引擎冒烟测试"""
import sys, os, io
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from engine.junk_cleaner import JunkCleaner
from engine.system_optimizer import SystemOptimizer

print("=== 1. 垃圾清理引擎 ===")
jc = JunkCleaner()
cats = jc._scan_all(lambda p, i: None)
for c in cats:
    print(f"[{c['id']}] {c['name']}: {c['file_count']} files, {c['size_text']}")
total = sum(c['total_bytes'] for c in cats)
print(f"TOTAL: {total} bytes")

print()
print("=== 2. 垃圾清理执行（temp_files）===")
res = jc.execute_clean(["temp_files"])
print("success:", res.get("success"), "| freed:", res.get("freed_text"),
      "| cleaned:", res.get("cleaned_files"), "| failed:", res.get("failed_count"))

print()
print("=== 3. 历史记录 ===")
hist = jc.get_history(3)
print("records:", len(hist))

print()
print("=== 4. 电脑优化-体检 ===")
so = SystemOptimizer()
ov = so.overview()
print("score:", ov["score"])
for c in ov["checks"]:
    print(f"  [{c['status']}] {c['name']}: {c['detail']}")
print("disk:", ov["disk"]["free_text"], "/", ov["disk"]["total_text"])
print("mem:", ov["memory"]["used_text"], "/", ov["memory"]["total_text"],
      f"({ov['memory']['used_percent']:.1f}%)")
print("temp:", ov["temp"]["size_text"], "| startup:", ov["startup_count"], "| reboot:", ov["pending_reboot"])

print()
print("=== 5. 启动项列表 ===")
items = so.list_startup()
print("count:", len(items))
for it in items[:8]:
    print(f"  [{it['status']}] {it['name']} | {it.get('source','')[:60]}")

print()
print("=== 6. 服务列表 ===")
svcs = so.list_services()
print("manageable:", svcs["manageable_count"], "| readonly:", svcs["readonly_count"])
for s in svcs["manageable"][:5]:
    print(f"  [{s['start_type']}] {s['display']} | {s['image_path'][:50]}")

print()
print("=== 7. 内存释放 ===")
mem = so.release_memory()
print("success:", mem.get("success"), "| released:", mem.get("released_text"),
      "| processed:", mem.get("processed"))

print()
print("=== 8. 一键优化（不自动禁用启动项）===")
one = so.one_click()
print("success:", one.get("success"))
print("clean:", one.get("clean", {}).get("freed_text"))
print("memory:", one.get("memory", {}).get("released_text"))
print("recommendations:", len(one.get("recommendations", [])))
for r in one.get("recommendations", [])[:5]:
    print(f"  - {r['name']} | {r['source'][:60]}")

print()
print("ALL SMOKE TESTS DONE")
