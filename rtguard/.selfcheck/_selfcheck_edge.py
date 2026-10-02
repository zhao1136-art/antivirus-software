import ast
import ctypes
import os
import sys
import tempfile

sys.path.insert(0, r"H:\Caelire\rtguard")

import rtguard.quarantine as q
import rtguard.tray as tray

print("== 附加验证 ==")

# 1) Quarantine：嵌套不存在的目录应被创建
root = tempfile.mkdtemp(prefix="rtg_edge_")
deep = os.path.join(root, "a", "b", "q")
qq = q.Quarantine(deep)
print("1) 嵌套目录创建:", os.path.isdir(deep))

# 2) restore(dest=None) 且 original_path 为空 -> KeyError，不写坏文件
src = os.path.join(root, "f.bin")
with open(src, "wb") as fh:
    fh.write(b"x" * 100)
info = qq.add(src)
idx_path = os.path.join(deep, "index.json")
import json
with open(idx_path, "r", encoding="utf-8") as fh:
    raw = json.load(fh)
raw["entries"][info["id"]]["original_path"] = ""
with open(idx_path, "w", encoding="utf-8") as fh:
    json.dump(raw, fh)
q2 = q.Quarantine(deep)
try:
    q2.restore(info["id"])
    print("2) restore(None, 空原路径): 未抛异常（异常！）")
except KeyError:
    print("2) restore(None, 空原路径): 正确抛 KeyError")

# 3) 只读/不可写 qdir 不应让构造抛异常？qdir 必须可写才能创建，这里验证正常路径
print("3) Quarantine(qdir) 幂等:", q.Quarantine(deep).qdir == q.Quarantine(deep).qdir)

# 4) tray 无桌面会话的优雅失败：把 _IS_WINDOWS 关掉模拟不可用平台
orig = tray._IS_WINDOWS
tray._IS_WINDOWS = False
try:
    t = tray.TrayIcon("x")
    print("4) 非 Windows 平台 start() =", t.start(), "| last_error =", t.last_error)
    print("   notify() =", t.notify("a", "b"), "| stop() 未抛异常: True")
    t.stop()
finally:
    tray._IS_WINDOWS = orig

# 5) Shell_NotifyIconW 返回 0 的路径：伪造一个无效 hwnd，强制走失败分支
add = tray._Shell_NotifyIconW
class Fake:
    def __call__(self, *a):
        return 0
tray._Shell_NotifyIconW = Fake()
try:
    t2 = tray.TrayIcon("y")
    r = t2.start()
    print("5) 模拟 Shell_NotifyIconW 返回 0 -> start() =", r, "| last_error =", t2.last_error)
    t2.stop()
    print("   start() 未抛异常: True")
finally:
    tray._Shell_NotifyIconW = add

# 6) 第三方依赖扫描：只用标准库
stdlib = set(sys.stdlib_module_names)
for path in (r"H:\Caelire\rtguard\rtguard\quarantine.py", r"H:\Caelire\rtguard\rtguard\tray.py"):
    tree = ast.parse(open(path, encoding="utf-8").read())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                mods.add(node.module.split(".")[0])
    third = sorted(m for m in mods if m not in stdlib and m != "__future__")
    print(f"6) {os.path.basename(path)} imports = {sorted(mods)} | 第三方 = {third or '无'}")

# 7) 关键接口齐全性
need_q = {"add", "list", "restore", "delete", "get"}
need_t = {"start", "stop", "notify"}
print("7) Quarantine 接口齐全:", need_q <= set(dir(q.Quarantine)))
print("   TrayIcon 接口齐全  :", need_t <= set(dir(tray.TrayIcon)))
print("   callable() 回调校验: on_open 非可调用时被丢弃 ->", tray.TrayIcon("z", on_open=123).on_open is None)

# 8) add() 混淆阶段失败必须回滚：源文件回到原位，隔离区不留明文
root2 = os.path.join(root, "rollback")
os.makedirs(root2)
src2 = os.path.join(root2, "plain.bin")
payload = b"SECRET-PLAINTEXT" * 1000
with open(src2, "wb") as fh:
    fh.write(payload)
qdir2 = os.path.join(root2, "q")
qr = q.Quarantine(qdir2)
saved = q._xor_stream


def _boom(*a, **k):
    raise OSError("boom")


q._xor_stream = _boom
try:
    qr.add(src2)
    print("8) 回滚测试: 竟然没抛异常（异常！）")
except OSError as exc:
    files = sorted(os.listdir(qdir2))
    print("8) 混淆失败抛出:", exc)
    print("   源文件已复原:", os.path.exists(src2),
          "内容完整:", open(src2, "rb").read() == payload)
    print("   隔离目录残留:", [f for f in files if f != "index.json"] or "无 .qfile 残留")
    print("   索引条目数  :", len(qr.list()))
finally:
    q._xor_stream = saved

# 9) delete() 幂等 & 不存在的 id
print("9) delete(不存在) ->", qr.delete("nope"))

# 10) tmp 残留清理
print("10) 隔离目录内 .tmp 文件:", [f for f in os.listdir(qdir2) if f.endswith(".tmp")] or "无")

os.system("")  # flush
import shutil
shutil.rmtree(root, ignore_errors=True)
print("EDGE CHECKS DONE")
