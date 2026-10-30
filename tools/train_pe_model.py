"""训练 Caelire 的 PE 机器学习模型，并导出 ONNX + features.json 契约。

数据集全部来自本机，无需下载：
  良性 —— System32 / SysWOW64 / Program Files / LocalAppData\\Programs / G:\\
  恶意 —— H:\\御天防护型AI\\training_samples\\*.zip

设计要点（都是踩过的坑）：
  · 按 SHA256 去重：WinSxS / Program Files 里同一 DLL 有多份副本，不去重会让
    训练集与测试集互相泄漏，评估结果虚高。
  · 按“来源组”切分（良性=厂商目录，恶意=zip 文件），不是随机切分 —— 否则
    近重复样本会横跨两侧。
  · 特征提取用多进程：单文件实测约 0.13s/MB，6000 样本单进程要十几分钟。
  · 导出 ONNX 时同时写 features.json 契约（维度 + 特征顺序 + 提取器指纹），
    加载端据此校验，防止“模型与特征器版本错配”这种最隐蔽的错误。

用法：
  python tools\\train_pe_model.py --pilot          # 小规模试跑，验证链路
  python tools\\train_pe_model.py --benign 3000 --malware 3000
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import sys
import tempfile
import time
import zipfile

BACKEND = r"H:\Caelire\backend"
sys.path.insert(0, BACKEND)

PE_EXT = (".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl")

BENIGN_ROOTS = [
    (r"C:\Windows\System32", "sys32"),
    (r"C:\Windows\SysWOW64", "wow64"),
    (r"C:\Program Files", "pf"),
    (r"C:\Program Files (x86)", "pf86"),
    (os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs"), "userapp"),
    (r"G:\\", "gdrive"),
]

MALWARE_DIR = r"H:\御天防护型AI\training_samples"

# 解压目录放 G 盘：恶意样本解出来体积不小（2.5GB 压缩包 → 更大），
# 而且**持久保存**，重跑训练时复用，不必反复解压。
DEFAULT_WORKDIR = r"G:\andun_train_work"

OUT_DIR = r"H:\Caelire\backend\engine\models"

# 收集良性时**必须排除**的路径。
# 最要紧的是训练自己的解压缓存：G:\andun_train_work\malware 里全是解压出来的
# 恶意样本，而 collect_benign 会扫 G:\ 整盘 —— 不排除就会把恶意样本当良性
# 喂进训练集（实测曾混入 294/3000 ≈ 9.8%，是典型的标签污染，会让评估结果
# 和最终模型都不可信）。
EXCLUDE_PREFIXES = [
    os.path.normcase(DEFAULT_WORKDIR),
    os.path.normcase(os.path.join(BACKEND, "dist")),
    os.path.normcase(os.path.join(BACKEND, "build")),
]


def _excluded(path: str) -> bool:
    """路径是否落在必须排除的前缀下。"""
    p = os.path.normcase(os.path.abspath(path))
    for x in EXCLUDE_PREFIXES:
        if p == x or p.startswith(x + os.sep):
            return True
    return False


# ── 工具 ──────────────────────────────────────────────────────────
def sha256_file(path: str, limit: int = 64 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b)
    except OSError:
        return ""
    return h.hexdigest()


def collect_benign(limit: int, seed: int = 42) -> list[tuple[str, str]]:
    """返回 [(path, group)]；group 用于分组切分。"""
    rng = random.Random(seed)
    per_root = []
    for root, tag in BENIGN_ROOTS:
        if not root or not os.path.isdir(root):
            continue
        found = []
        base_depth = root.rstrip("\\").count(os.sep)
        max_depth = 6 if tag == "gdrive" else 12
        for dp, dns, fns in os.walk(root):
            if _excluded(dp):
                dns[:] = []
                continue
            # 剪枝：不下探排除目录与 __pycache__
            dns[:] = [d for d in dns
                      if d != "__pycache__"
                      and not _excluded(os.path.join(dp, d))]
            if dp.count(os.sep) - base_depth > max_depth:
                dns[:] = []
                continue
            for f in fns:
                if not f.lower().endswith(PE_EXT):
                    continue
                p = os.path.join(dp, f)
                try:
                    if not (4096 <= os.path.getsize(p) <= 64 * 1024 * 1024):
                        continue
                except OSError:
                    continue
                # group = 相对路径的第一段（厂商/程序目录）
                rel = os.path.relpath(dp, root).split(os.sep)
                group = f"{tag}/{rel[0] if rel and rel[0] != '.' else '_root'}"
                found.append((p, group))
        rng.shuffle(found)
        per_root.append((tag, found))
        print(f"  良性候选 {tag:8} {len(found):>6}")

    # 目标配比：**刻意压低系统文件占比**。
    # 系统文件全部微软签名、结构雷同，占比过高会让模型只学到"微软签名=良性"，
    # 对第三方软件/安装包/加壳程序大量误报 —— 而那才是用户真正下载的东西。
    # 所以把权重向 Program Files / G 盘安装包 / 用户级安装倾斜。
    QUOTA = {
        "sys32": 0.18, "wow64": 0.09, "pf": 0.24, "pf86": 0.24,
        "userapp": 0.07, "gdrive": 0.18,
    }
    picked: list[tuple[str, str]] = []
    leftovers: list[tuple[str, str]] = []
    for tag, found in per_root:
        want = int(limit * QUOTA.get(tag, 0.0))
        take = found[:want]
        picked.extend(take)
        leftovers.extend(found[want:])
    # 没取满（某些来源不够）就从各来源剩余里补齐
    if len(picked) < limit:
        rng.shuffle(leftovers)
        picked.extend(leftovers[: limit - len(picked)])

    # ── 按 SHA256 去重（良性侧原先**完全没有去重**）──
    # WinSxS / Program Files / G 盘安装包里同一个 DLL 常有多个副本，
    # 不去重会让训练集里出现成对的近重复样本：不仅虚增样本量，
    # 一旦它们被分到训练/测试两侧，评估指标就会明显虚高。
    # （sha256_file 此前定义了却从未被调用 —— 是死代码，这里接上。）
    uniq: list[tuple[str, str]] = []
    seen_hash: set[str] = set()
    dropped = 0
    for p, g in picked:
        d = sha256_file(p)
        if not d:
            continue
        if d in seen_hash:
            dropped += 1
            continue
        seen_hash.add(d)
        uniq.append((p, g))
    # 去重后不足 limit 时，从剩余候选里继续补（同样查重）
    if len(uniq) < limit:
        for p, g in leftovers:
            if len(uniq) >= limit:
                break
            if (p, g) in picked:
                continue
            d = sha256_file(p)
            if not d or d in seen_hash:
                continue
            seen_hash.add(d)
            uniq.append((p, g))
    if dropped:
        print(f"  良性去重：剔除 {dropped} 个重复样本，剩余 {len(uniq)}")
    rng.shuffle(uniq)
    return uniq[:limit]


def collect_malware(limit: int, workdir: str, reuse: bool = True,
                    password: str = "infected", jobs: int = 3) -> list[tuple[str, str]]:
    """从 zip 里解出 PE 到 workdir（持久缓存），返回 [(path, group)]；group=zip 名。

    这些样本包**全部有密码**（ZipCrypto），密码是恶意样本圈的标准约定
    `infected`。注意 `御天防护型AI/monitor_data/seal_passphrase.txt` 那个
    口令**不适用** —— 它是该项目自己 AES 封存样本用的。

    缓存布局：<workdir>/malware/<zip 名>/<sha256><ext>
      · 用 sha256 当文件名 → 天然去重，跨 zip 重复样本只留一份
      · 按 zip 分子目录 → group 就是 zip 名，供分组切分使用
      · 已存在的文件直接跳过，重跑训练不重复解压
    """
    if not os.path.isdir(MALWARE_DIR):
        print(f"  !! 恶意样本目录不存在: {MALWARE_DIR}")
        return []

    pwd = password.encode("utf-8") if password else None
    out_root = os.path.join(workdir, "malware")
    os.makedirs(out_root, exist_ok=True)

    dropped = {"n": 0}

    def _scan_existing():
        found = []
        for d in sorted(os.listdir(out_root)):
            dp = os.path.join(out_root, d)
            if not os.path.isdir(dp):
                continue
            for f in os.listdir(dp):
                if not f.lower().endswith(PE_EXT):
                    continue
                p = os.path.join(dp, f)
                # 校验文件头：进程被中断/写失败可能留下截断文件，
                # 绝不能让它进训练集（会变成"标签正确、特征垃圾"的毒样本）
                try:
                    if os.path.getsize(p) < 1024:
                        dropped["n"] += 1
                        continue
                    with open(p, "rb") as fh:
                        if fh.read(2) != b"MZ":
                            dropped["n"] += 1
                            continue
                except OSError:
                    dropped["n"] += 1
                    continue
                found.append((p, f"mal/{d}"))
        return found

    existing = _scan_existing() if reuse else []
    if existing:
        print(f"  复用已解出样本 {len(existing)} 个（{out_root}）")
    if len(existing) >= limit:
        rng = random.Random(7)
        rng.shuffle(existing)
        return existing[:limit]

    picked = list(existing)
    seen = {os.path.splitext(os.path.basename(p))[0] for p, _g in picked}

    zips = sorted(f for f in os.listdir(MALWARE_DIR) if f.lower().endswith(".zip"))
    rng = random.Random(7)
    rng.shuffle(zips)

    # 并行解压：一个 zip 一个任务，按剩余额度分摊。
    # 单进程解密 2.57GB 在 4 核 Athlon 上要 70 分钟以上，而另外 3 个核是闲着的。
    from concurrent.futures import ProcessPoolExecutor, as_completed

    remaining = max(1, limit - len(picked))
    per_zip = max(1, (remaining + len(zips) - 1) // max(1, len(zips)))
    tasks = []
    for zname in zips:
        tag = os.path.splitext(zname)[0].replace(" ", "_")
        tasks.append((os.path.join(MALWARE_DIR, zname),
                      os.path.join(out_root, tag), per_zip, password))
    total_fail = 0
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futs = {pool.submit(_extract_zip, t): t[0] for t in tasks}
        for fut in as_completed(futs):
            try:
                zname, got, fails = fut.result()
            except Exception as exc:
                print(f"  !! 解压任务失败 {os.path.basename(futs[fut])}: {exc}")
                continue
            total_fail += fails
            if got or fails:
                print(f"  恶意 {zname:34} 新增 {got:>5} 失败 {fails:>4}", flush=True)
    if total_fail:
        print(f"  解密/读取失败合计 {total_fail}")

    # 重新扫描磁盘并去重（跨 zip 的重复样本只留一份）
    by_stem = {}
    for p, g in _scan_existing():
        stem = os.path.splitext(os.path.basename(p))[0]
        by_stem.setdefault(stem, (p, g))
    picked = list(by_stem.values())
    print(f"  解压后去重共 {len(picked)} 个")
    if len(picked) > limit:
        rng.shuffle(picked)
        picked = picked[:limit]
    return picked


def _extract_zip(task):
    """解压单个 zip 中最多 want 个尚未落盘的 PE；返回 (zip 名, 成功数, 失败数)。

    独立成模块级函数是为了能被 ProcessPoolExecutor 序列化调用。
    """
    zpath, zdir, want, password = task
    pwd = password.encode("utf-8") if password else None
    zname = os.path.basename(zpath)
    got = fails = 0
    try:
        with zipfile.ZipFile(zpath) as zf:
            for name in zf.namelist():
                if got >= want:
                    break
                if not name.lower().endswith(PE_EXT):
                    continue
                ext = os.path.splitext(name)[1].lower()
                stem = os.path.splitext(os.path.basename(name))[0].lower()
                looks_sha = len(stem) == 64 and all(
                    ch in "0123456789abcdef" for ch in stem)
                # 文件名即 sha256 → 已落盘的直接跳过，**不必解密**
                if looks_sha and os.path.isfile(os.path.join(zdir, stem + ext)):
                    continue
                try:
                    info = zf.getinfo(name)
                    if not (4096 <= info.file_size <= 64 * 1024 * 1024):
                        continue
                    data = zf.read(name, pwd=pwd)
                except Exception:
                    fails += 1
                    continue
                digest = stem if looks_sha else hashlib.sha256(data).hexdigest()
                try:
                    os.makedirs(zdir, exist_ok=True)
                    dst = os.path.join(zdir, digest + ext)
                    if not os.path.isfile(dst):
                        with open(dst, "wb") as f:
                            f.write(data)
                except OSError:
                    fails += 1
                    continue
                got += 1
    except Exception:
        pass
    return zname, got, fails


# ── 特征提取（多进程）──────────────────────────────────────────────
_WORKER_EX = None


def _worker_init():
    global _WORKER_EX
    from engine.ml_scanner import PEFeatureExtractor
    _WORKER_EX = PEFeatureExtractor()


def _worker_feat(args):
    idx, path = args
    try:
        with open(path, "rb") as f:
            data = f.read()
        # ⚠️ 与线上推理用**同一个**分析长度上限（config.ML_ANALYSIS_MAX_BYTES）。
        # 原先训练读整个文件、线上 sample_analyzer 只喂前 4MB —— 同一个文件
        # 在两边得到不同的 2381 维向量，模型学的分布和线上喂的对不上。
        import config as _cfg
        _cap = int(getattr(_cfg, "ML_ANALYSIS_MAX_BYTES", 32 * 1024 * 1024))
        if len(data) > _cap:
            data = data[:_cap]
        return idx, _WORKER_EX.feature_vector(data), ""
    except Exception as exc:
        return idx, None, f"{type(exc).__name__}: {exc}"


def extract_features(items, jobs: int, label: str, dim: int):
    import numpy as np
    from concurrent.futures import ProcessPoolExecutor

    n = len(items)
    X = np.zeros((n, dim), dtype=np.float32)
    ok = 0
    t0 = time.perf_counter()
    with ProcessPoolExecutor(max_workers=jobs, initializer=_worker_init) as pool:
        for idx, fv, err in pool.map(_worker_feat,
                                     [(i, p) for i, (p, _g) in enumerate(items)],
                                     chunksize=8):
            if fv is None:
                continue
            X[idx] = fv
            ok += 1
            if ok % 200 == 0:
                el = time.perf_counter() - t0
                print(f"  [{label}] {ok}/{n}  {ok/el:.1f} 个/秒", flush=True)
    print(f"  [{label}] 完成 {ok}/{n}，耗时 {time.perf_counter()-t0:.0f}s", flush=True)
    return X


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true", help="小规模试跑")
    ap.add_argument("--benign", type=int, default=3000)
    ap.add_argument("--malware", type=int, default=3000)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=400)
    ap.add_argument("--leaves", type=int, default=127)
    ap.add_argument("--holdout", type=float, default=0.2)
    ap.add_argument("--out", default=OUT_DIR)
    ap.add_argument("--workdir", default=DEFAULT_WORKDIR,
                    help="恶意样本解压缓存目录（默认 G 盘，持久复用）")
    ap.add_argument("--no-reuse", action="store_true",
                    help="忽略已有缓存，重新解压")
    ap.add_argument("--clean", action="store_true",
                    help="结束后删除缓存目录（默认保留）")
    ap.add_argument("--password", default="infected",
                    help="恶意样本 zip 的解压密码（标准约定 infected）")
    args = ap.parse_args()

    if args.pilot:
        args.benign = 250
        args.malware = 250
        args.rounds = 120
        print("=== 试点模式：250 + 250 ===")

    import numpy as np

    t_start = time.time()
    workdir = args.workdir
    os.makedirs(workdir, exist_ok=True)
    print(f"\n[1/6] 收集样本  (解压缓存目录 {workdir})")
    benign = collect_benign(args.benign)
    print(f"  良性合计 {len(benign)}")
    malware = collect_malware(args.malware, workdir, reuse=not args.no_reuse,
                              password=args.password, jobs=args.jobs)
    print(f"  恶意合计 {len(malware)}")

    if len(benign) < 20 or len(malware) < 20:
        print("!! 样本不足，中止")
        return 2

    print("\n[2/6] 提取特征（多进程）")
    dim = 2381
    from engine.ml_scanner import PEFeatureExtractor
    dim = len(PEFeatureExtractor().feature_vector(b""))

    X_b = extract_features(benign, args.jobs, "benign", dim)
    X_m = extract_features(malware, args.jobs, "malware", dim)

    y_b = np.zeros(len(benign), dtype=np.int32)
    y_m = np.ones(len(malware), dtype=np.int32)
    X = np.vstack([X_b, X_m])
    y = np.concatenate([y_b, y_m])
    groups = np.array([g for _p, g in benign] + [g for _p, g in malware])
    print(f"  特征矩阵 {X.shape}  ({X.nbytes/1048576:.0f} MB)")

    print("\n[3/6] 分组切分")
    rng = np.random.RandomState(2026)
    uniq = np.unique(groups)
    rng.shuffle(uniq)
    n_hold = max(1, int(len(uniq) * args.holdout))
    hold_groups = set(uniq[:n_hold])
    mask_hold = np.array([g in hold_groups for g in groups])
    X_tr, y_tr = X[~mask_hold], y[~mask_hold]
    X_te, y_te = X[mask_hold], y[mask_hold]
    print(f"  训练 {len(y_tr)}（恶意 {int(y_tr.sum())}） / 测试 {len(y_te)}（恶意 {int(y_te.sum())}）")
    if len(y_te) == 0 or y_te.min() == y_te.max():
        print("!! 切分后测试集单一类别，改用随机切分")
        idx = rng.permutation(len(y))
        cut = int(len(y) * (1 - args.holdout))
        X_tr, y_tr, X_te, y_te = X[idx[:cut]], y[idx[:cut]], X[idx[cut:]], y[idx[cut:]]

    print("\n[4/6] 训练 LightGBM")
    import lightgbm as lgb
    params = {
        "objective": "binary",
        "metric": "auc",
        "boosting_type": "gbdt",
        "num_leaves": args.leaves,
        "learning_rate": 0.08,
        "feature_fraction": 0.6,
        "bagging_fraction": 0.8,
        "bagging_freq": 1,
        "min_data_in_leaf": 30,
        "num_threads": 4,
        "verbose": -1,
        "seed": 2026,
    }
    dtr = lgb.Dataset(X_tr, label=y_tr)
    dva = lgb.Dataset(X_te, label=y_te, reference=dtr)
    booster = lgb.train(params, dtr, num_boost_round=args.rounds,
                        valid_sets=[dva], valid_names=["holdout"],
                        callbacks=[lgb.early_stopping(40, verbose=False),
                                   lgb.log_evaluation(50)])

    print("\n[5/6] 评估")
    pred = booster.predict(X_te, num_iteration=booster.best_iteration)
    from sklearn.metrics import roc_auc_score, confusion_matrix
    try:
        auc = roc_auc_score(y_te, pred)
    except Exception:
        auc = float("nan")
    cm = confusion_matrix(y_te, (pred >= 0.5).astype(int), labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    print(f"  AUC       = {auc:.4f}")
    print(f"  阈值 0.5  → TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  召回 = {tp/max(1,tp+fn):.3f}   精确 = {tp/max(1,tp+fp):.3f}")
    print(f"  测试集误报率 FP/(FP+TN) = {fp/max(1,fp+tn):.3f}")
    print(f"  树数 = {booster.best_iteration or booster.num_trees()}")

    print("\n[6/6] 导出")
    os.makedirs(args.out, exist_ok=True)
    lgb_path = os.path.join(args.out, "pe_model.txt")
    booster.save_model(lgb_path, num_iteration=booster.best_iteration)
    print(f"  LightGBM 文本模型 -> {lgb_path} "
          f"({os.path.getsize(lgb_path)/1048576:.1f} MB)")

    # ONNX 导出
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    onnx_model = convert_lightgbm(
        booster, initial_types=[("input", FloatTensorType([None, dim]))],
        zipmap=False)
    onnx_path = os.path.join(args.out, "pe_model.onnx")
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"  ONNX 模型         -> {onnx_path} "
          f"({os.path.getsize(onnx_path)/1048576:.1f} MB)")

    # features.json 契约
    # 记录提取器源码指纹：加载端可据此发现"特征器改了但模型没重训"——
    # 那是这类 ML 最隐蔽的失效方式（模型还在、输出却是垃圾）。
    try:
        with open(os.path.join(BACKEND, "engine", "ml_scanner.py"), "rb") as f:
            ext_hash = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        ext_hash = ""
    # 行为指纹：在固定输入上算的特征向量，加载端据此判断"特征器是否变过"。
    # 比源文件哈希精确 —— 改注释/加接线不会误报，改特征语义一定不同。
    try:
        from engine.ember_onnx import extractor_probe_vector
        ext_probe = extractor_probe_vector()
    except Exception as exc:
        print(f"  !! 行为指纹生成失败: {exc}")
        ext_probe = None
    feature_order = build_feature_names(dim)
    contract = {
        "schema": 1,
        "dim": dim,
        "feature_version": 2,
        "extractor": "engine.ml_scanner.PEFeatureExtractor(feature_version=2)",
        "extractor_sha256": ext_hash,
        "extractor_probe": ext_probe,
        # 训练时用的分析长度上限；线上若与 config.ML_ANALYSIS_MAX_BYTES 不一致，
        # 同一个文件会被截成不同长度 → 特征分布偏移。加载端据此比对并告警。
        "analysis_max_bytes": int(getattr(
            __import__("config"), "ML_ANALYSIS_MAX_BYTES", 32 * 1024 * 1024)),
        "model_file": "pe_model.onnx",
        "lightgbm_file": "pe_model.txt",
        # 张量名写进契约，加载端不写死。LightGBM 转换出来的 ONNX 有
        # label(int64, shape[1]) 和 probabilities([None,2]) 两个输出，
        # 取错 label 会得到 0/1 标签而不是概率 —— 这是个安静的坑。
        "onnx": {
            "model_file": "pe_model.onnx",
            "input": "input",
            "output": "probabilities",
            "positive_index": 1,
        },
        "feature_order": feature_order,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "train": {"n": int(len(y_tr)), "malware": int(y_tr.sum())},
        "holdout": {"n": int(len(y_te)), "malware": int(y_te.sum()),
                    "auc": float(auc), "recall": float(tp / max(1, tp + fn)),
                    "precision": float(tp / max(1, tp + fp)),
                    "fpr": float(fp / max(1, fp + tn))},
        "params": params,
        "note": "自训练模型，非 EMBER 官方基准；仅作信号，不应赋予处置权",
    }
    cpath = os.path.join(args.out, "features.json")
    with open(cpath, "w", encoding="utf-8") as f:
        json.dump(contract, f, ensure_ascii=False, indent=2)
    print(f"  特征契约 features.json -> {cpath}")

    # 解压出的恶意样本默认保留在 workdir（G 盘），下次训练直接复用。
    if args.clean:
        shutil.rmtree(workdir, ignore_errors=True)
        print(f"\n已清理缓存目录 {workdir}")
    else:
        n_cached = sum(len(fs) for _d, _s, fs in os.walk(os.path.join(workdir, "malware")))
        print(f"\n缓存保留在 {workdir}（{n_cached} 个样本文件，下次直接复用）")
    print(f"总耗时 {(time.time()-t_start)/60:.1f} 分钟")
    return 0


def build_feature_names(dim: int) -> list[str]:
    """按段生成特征名，与实际拼接顺序一致。"""
    blocks = [("histogram", 256), ("byteentropy", 256), ("strings", 104),
              ("general", 10), ("header", 62), ("section", 255),
              ("imports", 1280), ("exports", 128), ("datadirectories", 30)]
    names: list[str] = []
    for prefix, n in blocks:
        names.extend(f"{prefix}_{i}" for i in range(n))
    if len(names) != dim:
        names = [f"f_{i}" for i in range(dim)]
    return names


if __name__ == "__main__":
    sys.exit(main())
