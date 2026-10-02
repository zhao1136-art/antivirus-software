"""前后端契约审计（一次性工具）：抽取后端路由 + 前端 API 调用并交叉比对。"""
import os
import re
import glob
import json

BASE = r"F:\Caelire\backend"


def backend_routes(app_py):
    """返回 (method, path) 集合，并支持参数化路径。"""
    routes = set()
    with open(app_py, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.match(r'\s*@app\.(get|post|put|delete|websocket)\s*\(\s*["\'](/[^"\']+)["\']', line)
            if m:
                routes.add((m.group(1).lower(), m.group(2)))
    return routes


def frontend_calls(files):
    """从 html/js 抽取 API URL（含模板字符串 ${...}）。返回 [(file, url_pattern)]"""
    calls = []
    pat = re.compile(r"/api/v1/[A-Za-z0-9/_{}$.\-]+|/api/health")
    for fp in files:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                if "/api/" not in line:
                    continue
                for hit in pat.findall(line):
                    calls.append((fp, i, hit))
    return calls


def norm_template(url):
    """把 ${...} template 转成可匹配的路径（参数段→*)"""
    return url.replace("${", "").replace("}", "").replace("'", "")


def match(frontend_url, backend_routes):
    """判断前端 URL 是否有后端路由支撑。返回 (bool, candidates)"""
    fu = norm_template(frontend_url).strip('"')
    # 精确匹配
    for m, path in backend_routes:
        if path.strip('"').strip("'") == fu:
            return True, None
    # 参数化匹配：逐段比较，任意段可作参数
    fseg = [s for s in fu.split("/") if s]
    matches = []
    for _m, path in backend_routes:
        path = path.strip('"').strip("'")
        bseg = [s for s in path.split("/") if s]
        if len(fseg) != len(bseg):
            continue
        ok = True
        for a, b2 in zip(fseg, bseg):
            if a != b2 and not (b2.startswith("{") and b2.endswith("}")):
                ok = False
                break
        if ok:
            matches.append(path)
    return (len(matches) > 0), matches


def main():
    app_py = os.path.join(BASE, "app.py")
    routes = backend_routes(app_py)

    frontend_files = sorted(glob.glob(os.path.join(BASE, "frontend", "*.html")))
    staging = glob.glob(os.path.join(BASE, "_staging_jt", "**", "*.js"), recursive=True)
    frontend_files += staging

    calls = frontend_calls(frontend_files)

    # 去重 url（保留第一个出现位置）
    seen = {}
    for fp, ln, url in calls:
        seen.setdefault(url, (fp, ln))

    missing = []
    for url, (fp, ln) in sorted(seen.items()):
        ok, cands = match(url, routes)
        if not ok:
            missing.append((url, fp, ln, cands))

    print(f"后端路由数: {len(routes)}")
    print(f"前端页面/脚本数: {len(frontend_files)}")
    print(f"前端唯一 API 调用数: {len(seen)}")
    print(f"\n=== 前端调用但后端无匹配路由 ({len(missing)}) ===")
    for url, fp, ln, cands in missing:
        c = ", ".join(sorted(cands)[:4]) if cands else ""
        print(f"  {url}")
        print(f"      <-- {os.path.relpath(fp, BASE)}:{ln}  近似: {c or '无'}")
    return missing


if __name__ == "__main__":
    main()