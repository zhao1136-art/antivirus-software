# -*- coding: utf-8 -*-
"""临时测试：御天卫士 API 集成测试（TestClient 单进程模式）"""
import sys, os, io
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

print("=== 1. 体检 API ===")
r = client.get("/api/v1/optimize/overview")
print("status:", r.status_code)
d = r.json()
print("score:", d.get("score"), "| checks:", len(d.get("checks", [])))

print()
print("=== 2. 启动项 API ===")
r = client.get("/api/v1/optimize/startup")
print("status:", r.status_code, "| items:", len(r.json().get("items", [])))

print()
print("=== 3. 服务列表 API ===")
r = client.get("/api/v1/optimize/services")
d = r.json()
print("status:", r.status_code,
      "| manageable:", d.get("manageable_count"), "| readonly:", d.get("readonly_count"))

print()
print("=== 4. 垃圾清理扫描 API ===")
r = client.post("/api/v1/clean/scan")
print("status:", r.status_code)
task_id = r.json().get("task_id")
print("task_id:", task_id)
import time
for _ in range(30):
    s = client.get(f"/api/v1/clean/{task_id}/status").json()
    if s["status"] in ("completed", "failed"):
        break
    time.sleep(0.5)
print("final status:", s["status"], "| progress:", s.get("progress"))
if s.get("result"):
    for c in s["result"]["categories"]:
        print(f"  [{c['id']}] {c['name']}: {c['file_count']} files, {c.get('size_text')}")

print()
print("=== 5. 清理执行 API（browser_cache 已扫描到的项）===")
cats = (s.get("result") or {}).get("categories") or []
ids = [c["id"] for c in cats if c["id"] != "recycle_bin" and c["file_count"] > 0]
print("executing:", ids)
r = client.post("/api/v1/clean/execute", json={"category_ids": ids})
d = r.json()
print("status:", r.status_code, "| success:", d.get("success"),
      "| freed:", d.get("freed_text"), "| cleaned:", d.get("cleaned_files"))

print()
print("=== 6. 清理历史 API ===")
r = client.get("/api/v1/clean/history")
print("status:", r.status_code, "| records:", len(r.json().get("records", [])))

print()
print("=== 7. 内存释放 API ===")
r = client.post("/api/v1/optimize/memory")
d = r.json()
print("status:", r.status_code, "| success:", d.get("success"), "| released:", d.get("released_text"))

print()
print("=== 8. 一键优化 API ===")
r = client.post("/api/v1/optimize/one-click")
d = r.json()
print("status:", r.status_code, "| success:", d.get("success"))
print("  clean freed:", (d.get("clean") or {}).get("freed_text"))
print("  memory:", (d.get("memory") or {}).get("released_text"))
print("  recommendations:", len(d.get("recommendations", [])))

print()
print("=== 9. 启动项 toggle（禁用/启用回环测试）===")
items = client.get("/api/v1/optimize/startup").json().get("items", [])
enabled = [it for it in items if it["status"] == "enabled"]
if enabled:
    it = enabled[0]
    r1 = client.post("/api/v1/optimize/startup/toggle", json={"item_id": it["item_id"], "action": "disable"})
    r2 = client.post("/api/v1/optimize/startup/toggle", json={"item_id": it["item_id"], "action": "enable"})
    print("disable:", r1.json().get("success"), r1.json().get("message", ""))
    print("enable :", r2.json().get("success"), r2.json().get("message", ""))
else:
    print("无可用启动项")

print()
print("=== 10. 前端页面可访问性 ===")
for page in ("guard.html", "clean.html", "optimize.html", "index.html", "scan.html"):
    r = client.get("/" + page)
    print(f"  {page}: HTTP {r.status_code}, len={len(r.text)}")
    if page in ("guard.html", "clean.html", "optimize.html") and "卫士" not in r.text:
        print("  WARN: 页面内容异常")

print()
print("ALL API TESTS DONE")
