"""
御天卫士 - 接口级冒烟测试

针对已运行的本地服务做核心链路回归，覆盖：
  1. 鉴权：未携带令牌的 /api/* 必须返回 401；带 Cookie 后正常放行
  2. 通用：/api/health（免鉴权）、/api/v1/version
  3. 扫描：发起快速扫描 → 轮询状态 → 正常结束
  4. 工具：体检 / 垃圾扫描（仅扫描不清理，避免改动用户环境）
  5. 云状态：确认新增的 degraded / missing_keys / hint 字段存在

用法（需先启动服务）：
  python tests/smoke_test.py                     # 默认 http://127.0.0.1:8899
  python tests/smoke_test.py --base-url http://127.0.0.1:8899 --timeout 120

退出码：
  0 = 全部通过；1 = 任一项失败
"""
import argparse
import sys
import time

import requests


def make_session(base_url: str) -> requests.Session:
    """先访问首页拿鉴权 Cookie，返回已就绪的会话"""
    s = requests.Session()
    r = s.get(base_url + "/", timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"首页不可达: HTTP {r.status_code}")
    if not any(c.name == "yt_token" for c in s.cookies):
        raise RuntimeError("未从首页响应中获得 yt_token 令牌 Cookie")
    return s


def check(name: str, ok: bool, detail: str = ""):
    """输出单条结果并累计失败数"""
    global _failures
    flag = "PASS" if ok else "FAIL"
    print(f"[{flag}] {name}" + (f" | {detail}" if detail else ""))
    if not ok:
        _failures += 1


_failures = 0


def poll_status(base_url: str, s: requests.Session, task_id: str, timeout: float = 120):
    """轮询扫描任务状态直至完成 / 失败 / 超时"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = s.get(f"{base_url}/api/v1/scan/{task_id}/status", timeout=10)
        data = r.json()
        status = data.get("status") or data.get("state") or ""
        if status in ("completed", "done", "finished", "success"):
            return True, data
        if status in ("failed", "error", "cancelled"):
            return False, data
        time.sleep(1.0)
    return None, {"timeout": True}


def main() -> int:
    global _failures
    parser = argparse.ArgumentParser(description="御天卫士接口冒烟测试")
    parser.add_argument("--base-url", default="http://127.0.0.1:8899")
    parser.add_argument("--timeout", type=float, default=120, help="扫描任务最大等待秒数")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    s = make_session(base)

    # 1) 健康检查（免鉴权）
    try:
        r = requests.get(base + "/api/health", timeout=10)
        check("健康检查 /api/health 可达", r.status_code == 200 and r.json().get("status") == "ok",
              f"HTTP {r.status_code}")
    except Exception as e:
        check("健康检查 /api/health 可达", False, str(e))

    # 2) 鉴权：无令牌访问必须被拦下
    try:
        r = requests.get(base + "/api/v1/version", timeout=10)
        check("鉴权拦截无令牌的 /api/v1/version", r.status_code == 401,
              f"HTTP {r.status_code}（期望 401）")
    except Exception as e:
        check("鉴权拦截无令牌的 /api/v1/version", False, str(e))

    # 3) 带 Cookie 后正常放行
    try:
        r = s.get(base + "/api/v1/version", timeout=10)
        check("带 Cookie 访问 /api/v1/version", r.status_code == 200,
              f"HTTP {r.status_code}")
    except Exception as e:
        check("带 Cookie 访问 /api/v1/version", False, str(e))

    # 4) 防护状态
    try:
        r = s.get(base + "/api/v1/protection/status", timeout=10)
        check("防护状态 /api/v1/protection/status", r.status_code == 200,
              f"HTTP {r.status_code}")
    except Exception as e:
        check("防护状态 /api/v1/protection/status", False, str(e))

    # 5) 快速扫描 → 轮询
    task_id = None
    try:
        r = s.post(base + "/api/v1/scan/quick", timeout=30)
        data = r.json()
        task_id = data.get("task_id")
        check("发起快速扫描 /api/v1/scan/quick", r.status_code == 200 and bool(task_id),
              f"HTTP {r.status_code} task_id={task_id}")
    except Exception as e:
        check("发起快速扫描 /api/v1/scan/quick", False, str(e))

    if task_id:
        finish, data = poll_status(base, s, task_id, args.timeout)
        if finish is True:
            check("快速扫描成功结束", True, f"扫描结果 {data.get('status')}")
        elif finish is False:
            check("快速扫描成功结束", False, f"任务失败: {data}")
        else:
            check("快速扫描成功结束", False, "任务超时未完成")

    # 6) 系统体检
    try:
        r = s.get(base + "/api/v1/optimize/overview", timeout=15)
        check("系统体检 /api/v1/optimize/overview", r.status_code == 200 and "score" in r.json(),
              f"HTTP {r.status_code}")
    except Exception as e:
        check("系统体检 /api/v1/optimize/overview", False, str(e))

    # 7) 垃圾扫描（只扫描不执行清理）
    clean_task = None
    try:
        r = s.post(base + "/api/v1/clean/scan", timeout=30)
        data = r.json()
        clean_task = data.get("task_id")
        check("垃圾扫描 /api/v1/clean/scan", r.status_code == 200 and bool(clean_task),
              f"HTTP {r.status_code} task_id={clean_task}")
    except Exception as e:
        check("垃圾扫描 /api/v1/clean/scan", False, str(e))

    # 8) 云状态降级字段
    try:
        r = s.get(base + "/api/v1/cloud/status", timeout=10)
        body = r.json()
        has_fields = isinstance(body, dict) and (
            "degraded" in body and "missing_keys" in body and "hint" in body
        )
        check("云状态包含 degraded/missing_keys/hint", r.status_code == 200 and has_fields,
              f"HTTP {r.status_code}")
    except Exception as e:
        check("云状态包含 degraded/missing_keys/hint", False, str(e))

    print(f"\n冒烟测试完成：{'全部通过' if _failures == 0 else f'{_failures} 项失败'}")
    return 0 if _failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())