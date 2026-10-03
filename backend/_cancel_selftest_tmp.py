"""临时自检脚本：验证取消基础设施真的能让后端停下来（跑完即删）。

不导入 app.py（避免和正在运行的 8899 服务抢资源/起线程），
只导入被改动的 engine 模块，直接驱动 cancel 路径。
"""
import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

FAIL = []


def check(name, cond, extra=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("  " + str(extra) if extra else ""))
    if not cond:
        FAIL.append(name)


print("== 1. JunkCleaner 扫描取消 ==")
from engine.junk_cleaner import JunkCleaner, CleanTask  # noqa: E402

jc = JunkCleaner()
t = jc.start_scan()
check("start_scan 返回 task_id", bool(t.task_id), t.task_id)
check("新任务未被取消", t.cancel_event.is_set() is False)
ok = jc.cancel_task(t.task_id)
check("cancel_task 返回 True", ok is True)
check("取消标志已置位", t.cancel_event.is_set() is True)
deadline = time.time() + 10
while t.status in ("queued", "running") and time.time() < deadline:
    time.sleep(0.05)
check("扫描线程在 10s 内退出", t.status in ("cancelled", "completed"), t.status)
check("任务状态为 cancelled 而非 completed", t.status == "cancelled", t.status)
check("to_dict 带 cancelled 字段", t.to_dict().get("cancelled") is True)
check("重复取消 running/终态任务返回 False", jc.cancel_task(t.task_id) is False)
check("未知 task_id 取消返回 False", jc.cancel_task("nope") is False)


print("== 2. JunkCleaner.execute_clean 取消（真取消令牌） ==")


class _Tok:
    def __init__(self):
        self.flag = False

    def is_cancelled(self):
        return self.flag

    def is_set(self):
        return self.flag


tok = _Tok()
tok.flag = True  # 一开始就取消 → 不应删除任何文件
r = jc.execute_clean(["temp_files"], cancel=tok)
check("已取消时 success 仍为 True（正常路径）", r.get("success") is True)
check("返回值带 cancelled=True", r.get("cancelled") is True)
check("已取消时未清理任何文件", r.get("cleaned_files") == 0, r.get("cleaned_files"))

tok2 = _Tok()  # 不取消 → 行为应与旧接口一致
r2 = jc.execute_clean(["temp_files"], cancel=tok2)
check("不取消时 cancelled=False", r2.get("cancelled") is False)
check("不取消时返回结构完备", set(["success", "freed_text", "cleaned_files", "categories"]).issubset(r2.keys()))
r3 = jc.execute_clean(["not_a_category"])
check("非法分类仍被拒绝", r3.get("success") is False, r3.get("error"))
r4 = jc.execute_clean([])
check("空分类仍被拒绝", r4.get("success") is False)


print("== 3. SystemOptimizer 取消 ==")
from engine.system_optimizer import SystemOptimizer  # noqa: E402

so = SystemOptimizer()
cancelled_tok = _Tok()
cancelled_tok.flag = True
ov = so.overview(cancel=cancelled_tok)
check("overview 立刻取消返回 {'cancelled': True}", ov.get("cancelled") is True, ov)
check("_temp_size 取消返回 None", SystemOptimizer._temp_size(cancel=cancelled_tok) is None)
mem = so.release_memory(cancel=cancelled_tok)
check("release_memory 取消返回 cancelled=True", mem.get("cancelled") is True, mem)
one = so.one_click(cancel=cancelled_tok)
check("one_click 取消返回 cancelled=True", one.get("cancelled") is True, list(one.keys()))
check("one_click 取消时不产生启动项建议", one.get("recommendations") == [])
# 不取消路径仍然可用
live_tok = _Tok()
ov2 = so.overview(cancel=live_tok)
check("overview 未取消时返回体检报告", isinstance(ov2.get("checks"), list) and len(ov2["checks"]) >= 4, ov2.get("score"))
check("overview 未取消时不含 cancelled", not ov2.get("cancelled"))


print("== 4. VulnFix 取消 ==")
from engine.vuln_fix import VulnFix  # noqa: E402

vf = VulnFix()
vf_cancel = _Tok()
vf_cancel.flag = True
rep = vf.scan(cancel=vf_cancel)
check("vuln scan 取消返回 cancelled=True", rep.get("cancelled") is True, rep)
rep2 = vf.scan(cancel=_Tok())
check("vuln scan 未取消返回完整报告", "installed_count" in rep2 and "all_patched" in rep2)


print("== 5. AntiRootkit 取消 ==")
from engine.anti_rootkit import AntiRootkit  # noqa: E402

ar = AntiRootkit()
ar_cancel = _Tok()
ar_cancel.flag = True
rr = ar.scan(cancel=ar_cancel)
check("rootkit scan 取消返回 cancelled=True", rr.get("cancelled") is True, {k: rr.get(k) for k in ('cancelled', 'total_threats')})
check("rootkit scan 取消后 _scanning 复位", ar._scanning is False)
ar2 = AntiRootkit()
rr2 = ar2.scan()
check("rootkit scan 未取消时正常返回", "total_threats" in rr2 and "verdict" in rr2)
check("rootkit scan 未取消时不含 cancelled=True", rr2.get("cancelled") is not True)
# 实例内 cancel()
ar3 = AntiRootkit()
ar3.cancel()
check("AntiRootkit.cancel()/is_cancelled() 生效", ar3.is_cancelled() is True)


print("== 6. DataRecovery 分块恢复取消 ==")
from engine.data_recovery import DataRecovery, _cancelled  # noqa: E402

check("_cancelled(None) == False", _cancelled(None) is False)
dr = DataRecovery()
import tempfile  # noqa: E402

d = tempfile.mkdtemp(prefix="yt_restore_test_")
src = os.path.join(d, "src.bin")
dst = os.path.join(d, "dst.bin")
with open(src, "wb") as f:
    f.write(b"A" * (3 * 1024 * 1024))
cancel_now = _Tok()
cancel_now.flag = True
try:
    DataRecovery._copy_file_chunked(src, dst, cancel=cancel_now)
    check("取消时 _copy_file_chunked 抛出取消信号", False, "no exception")
except Exception as e:
    check("取消时 _copy_file_chunked 抛出取消信号", type(e).__name__ == "_RestoreCancelled", type(e).__name__)
check("取消后未留下半截目标文件", not os.path.isfile(dst))
check("取消后未留下临时残留文件", not [f for f in os.listdir(d) if f.startswith(".yt_restore_")], os.listdir(d))
DataRecovery._copy_file_chunked(src, dst, cancel=_Tok())
check("未取消时复制成功且内容一致", os.path.getsize(dst) == 3 * 1024 * 1024)


print("== 7. Scheduler 取消状态不被 completed 覆盖 ==")
src_sched = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine", "scheduler.py"),
                 encoding="utf-8").read()
check("scheduler 处理 result['cancelled']", 'result.get("cancelled") or task.status == "cancelled"' in src_sched)
check("scheduler 取消时提前 return（跳过云端/隔离）", "task.status = \"cancelled\"" in src_sched)

print()
if FAIL:
    print("SELFTEST FAILED:", FAIL)
    sys.exit(1)
print("SELFTEST ALL PASSED")
