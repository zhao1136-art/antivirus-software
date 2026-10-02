import hashlib
import os
import shutil
import sys
import tempfile

sys.path.insert(0, r"H:\Caelire\rtguard")

from rtguard.quarantine import Quarantine

root = tempfile.mkdtemp(prefix="rtg_q_")
src_dir = os.path.join(root, "src")
qdir = os.path.join(root, "q")
restore_dir = os.path.join(root, "restore")
os.makedirs(src_dir)
os.makedirs(restore_dir)

sample = os.path.join(src_dir, "sample.bin")
data = os.urandom(1024 * 1024)  # 1 MiB 随机内容
with open(sample, "wb") as fh:
    fh.write(data)
orig_sha = hashlib.sha256(data).hexdigest()
print("临时目录 :", root)
print("原始文件 :", sample)
print("原始大小 :", len(data), "bytes")
print("原始sha256:", orig_sha)

q = Quarantine(qdir)
print("qdir 已创建:", os.path.isdir(qdir))

info = q.add(sample, meta={"threat": "EICAR-Test"})
print()
print("== add() ==")
for k in ("id", "size", "sha256", "original_path", "time"):
    print(f"  {k:14s}= {info[k]}")
assert info["sha256"] == orig_sha, "add 返回的 sha256 不是原始文件哈希"
assert info["size"] == len(data)
assert not os.path.exists(sample), "源文件应已被移走"

qfile = os.path.join(qdir, info["id"] + ".qfile")
print("隔离文件路径 :", qfile)
print("隔离文件存在 :", os.path.exists(qfile))
with open(qfile, "rb") as fh:
    stored = fh.read()
print("隔离文件大小 :", len(stored))
same_bytes = stored == data
diff_count = sum(1 for a, b in zip(stored, data) if a != b)
print("磁盘内容与原文是否逐字节相同 :", same_bytes)
print("逐字节不同的字节数           :", diff_count, "/", len(data))
assert not same_bytes, "隔离文件内容竟然与原文相同！"

print()
print("== 重复隔离同一路径（先重建源文件）==")
with open(sample, "wb") as fh:
    fh.write(data)
info2 = q.add(sample)
print("  id1 =", info["id"])
print("  id2 =", info2["id"])
assert info2["id"] != info["id"], "重复隔离生成了相同 id"
assert os.path.exists(qfile), "重复隔离覆盖了已有条目"
assert os.path.exists(os.path.join(qdir, info2["id"] + ".qfile"))
assert len(q.list()) == 2, "重复隔离后条目数应为 2"

print()
print("== restore() ==")
dest = os.path.join(restore_dir, "restored.bin")
written = q.restore(info["id"], dest)
print("  restore 返回路径 :", written)
with open(written, "rb") as fh:
    restored = fh.read()
res_sha = hashlib.sha256(restored).hexdigest()
print("  还原后 sha256    :", res_sha)
print("  sha256 == 原始   :", res_sha == orig_sha)
print("  字节完全一致     :", restored == data)
assert res_sha == orig_sha and restored == data, "还原失败"

print()
print("== restore() 到原路径 ==")
back = q.restore(info2["id"])
print("  restore 返回路径 :", back)
with open(back, "rb") as fh:
    back_sha = hashlib.sha256(fh.read()).hexdigest()
print("  原路径还原 sha256:", back_sha)
print("  sha256 == 原始   :", back_sha == orig_sha)
assert back == os.path.abspath(sample) and back_sha == orig_sha

print()
print("== list() / get() ==")
items = q.list()
print("  条目数:", len(items), "（应为 2）")
for it in items:
    print("   -", it["id"], it["name"], it["size"], it["sha256"][:16] + "...", round(it["time"], 3))
assert items[0]["time"] >= items[1]["time"], "list 未按时间倒序"
g = q.get(info["id"])
print("  get(id1).sha256 == 原始 sha256 :", g["sha256"] == orig_sha)
print("  get('deadbeef...') ->", q.get("deadbeefdeadbeef"))
assert q.get("deadbeefdeadbeef") is None
try:
    q.restore("deadbeefdeadbeef")
    raise AssertionError("不存在的 id 未抛 KeyError")
except KeyError:
    print("  restore(不存在) 正确抛 KeyError")
try:
    q.restore("deadbeefdeadbeef", dest)
except KeyError:
    pass

print()
print("== delete() ==")
print("  delete(id1) ->", q.delete(info["id"]))
print("  .qfile 已删除:", not os.path.exists(qfile))
print("  index 中已移除:", q.get(info["id"]) is None)
print("  delete(id1) 再次 ->", q.delete(info["id"]))
print("  剩余条目数:", len(q.list()))
assert not os.path.exists(qfile)
assert q.get(info["id"]) is None
assert len(q.list()) == 1

print()
print("== index.json 损坏恢复 ==")
with open(os.path.join(qdir, "index.json"), "w", encoding="utf-8") as fh:
    fh.write("{ this is not json")
q2 = Quarantine(qdir)
print("  损坏后新建实例条目数:", len(q2.list()), "（应为 0，不抛异常）")
broken = [n for n in os.listdir(qdir) if n.startswith("index.json.broken-")]
print("  备份文件:", broken)
assert broken, "损坏索引未备份"
probe = os.path.join(src_dir, "probe.bin")
with open(probe, "wb") as fh:
    fh.write(b"probe-data")
ip = q2.add(probe)
print("  损坏恢复后 add 仍可用:", ip["id"], "size=", ip["size"])

print()
print("== 大文件分块 & 跨块密钥连续性（3 MiB，非块大小整数倍）==")
big = os.path.join(src_dir, "big.bin")
bigdata = os.urandom(3 * 1024 * 1024 + 12345)
with open(big, "wb") as fh:
    fh.write(bigdata)
q3 = Quarantine(os.path.join(root, "q3"))
i3 = q3.add(big)
out3 = q3.restore(i3["id"], os.path.join(restore_dir, "big.out"))
with open(out3, "rb") as fh:
    big_out = fh.read()
print("  原始 sha256:", hashlib.sha256(bigdata).hexdigest())
print("  还原 sha256:", hashlib.sha256(big_out).hexdigest())
print("  完全一致   :", big_out == bigdata)
assert big_out == bigdata

shutil.rmtree(root, ignore_errors=True)
print()
print("ALL QUARANTINE CHECKS PASSED")
