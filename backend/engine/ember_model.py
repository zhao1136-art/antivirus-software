"""."""
from __future__ import annotations

import math
import os
import re
from typing import List, Optional

# EMBER 官方 LightGBM 模型（classifier.txt）的纯 Python 推理器。
# 无需安装 lightgbm 包：直接解析 LightGBM save_model 的文本树格式并前向求值。
# 模型文件缺失时返回 None，调用方应安全跳过（不影响原有规则评分链路）。


class EMBERPredictor:
    """解析并求值 EMBER 的 LightGBM 二分类模型。

    概率 = sigmoid( sigmoid_param * sum_over_trees( leaf_value ) )。
    ``sigmoid_param`` 取自模型头的 ``objective=binary sigmoid:X``（缺省 1.0），
    与 LightGBM 的 ConvertOutput 保持一致。
    """

    def __init__(self, trees, sigmoid: float = 1.0):
        self.trees = trees
        try:
            self.sigmoid = float(sigmoid)
        except (TypeError, ValueError):
            self.sigmoid = 1.0

    def predict_proba(self, features) -> float:
        """输入为 2381 维 EMBER v2 特征向量，返回恶意概率 0.0~1.0。"""
        raw = 0.0
        for tree in self.trees:
            raw += tree.eval(features)
        try:
            return 1.0 / (1.0 + math.exp(-self.sigmoid * raw))
        except (OverflowError, ValueError):
            return 1.0 if raw > 0 else 0.0


class _Tree:
    __slots__ = ("num_leaves", "split_feature", "threshold", "left_child",
                 "right_child", "decision_type", "leaf_value")

    def __init__(self):
        self.num_leaves = 0
        self.split_feature: List[int] = []
        self.threshold: List[float] = []
        self.left_child: List[int] = []
        self.right_child: List[int] = []
        self.decision_type: List[int] = []
        self.leaf_value: List[float] = []

    def eval(self, features) -> float:
        n = 0  # 根内部节点下标（经典格式：内部 0..N-2，叶子用负值引用）
        while True:
            if n < 0:
                return self.leaf_value[-n - 1]
            # 兼容紧凑格式：内部节点编号可能落在 [num_leaves, ...)
            idx = n - self.num_leaves if n >= self.num_leaves else n
            feat = self.split_feature[idx] if idx < len(self.split_feature) else 0
            val = features[feat] if feat < len(features) else 0.0
            thr = self.threshold[idx]
            if val <= thr:
                n = self.left_child[idx]
            else:
                n = self.right_child[idx]


# ---------------------------------------------------------------------------
# 模型文本解析
# ---------------------------------------------------------------------------
#
# ⚠️ 兼容性修正（2026-10-24）
# 原实现只按 `[Tree: N]` 切块，而 LightGBM 的 save_model()/model_to_string()
# 产出的是**标准格式** `Tree=0` / `Tree=1` ……（没有方括号和冒号）。
# 后果很危险：把官方 ember_model_2018.txt 放进来时，正则一处都匹配不到，
# 整份文本被当成**一个块**，重复出现的 split_feature / threshold / leaf_value
# 被后出现的覆盖 —— 于是"加载成功"但实际只剩**最后一棵树**，
# ml_status 还会显示 "ok"，而喂给判定的是垃圾概率。
# 现在两种头都支持，并且做三项校验：块数=树数、num_class 必须为 1、解析失败即拒绝。
_LGB_TREE_HEADER = re.compile(r"^\s*Tree=(\d+)\s*$", re.MULTILINE)
_LEGACY_TREE_HEADER = re.compile(r"^\s*\[Tree:\s*(\d+)\]\s*$", re.MULTILINE)
_INT_LIST = re.compile(r"^\s*([A-Za-z_]+)=(.*)$", re.MULTILINE)


def _split_tree_blocks(text: str) -> list:
    """按 `Tree=N`（标准）或 `[Tree: N]`（旧式）切出每棵树的正文。"""
    matches = list(_LGB_TREE_HEADER.finditer(text))
    if not matches:
        matches = list(_LEGACY_TREE_HEADER.finditer(text))
    if not matches:
        return []
    blocks = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        seg = text[start:end]
        # 最后一棵树后面跟着 "end of trees" / parameters / feature_importances，
        # 必须截掉，否则那些段里的同名键会污染解析。
        cut = seg.find("end of trees")
        if cut >= 0:
            seg = seg[:cut]
        blocks.append(seg)
    return blocks


def _parse_header_meta(text: str) -> dict:
    """从模型头读取 num_class 与 sigmoid 参数。"""
    meta = {"num_class": 1, "sigmoid": 1.0, "objective": ""}
    m = re.search(r"^num_class=(\d+)", text, re.MULTILINE)
    if m:
        try:
            meta["num_class"] = int(m.group(1))
        except ValueError:
            pass
    m = re.search(r"^objective=(.+)$", text, re.MULTILINE)
    if m:
        obj = m.group(1).strip()
        meta["objective"] = obj
        sm = re.search(r"sigmoid:([0-9.eE+-]+)", obj)
        if sm:
            try:
                meta["sigmoid"] = float(sm.group(1))
            except ValueError:
                pass
    return meta


def _parse_tree_block(block: str) -> Optional[_Tree]:
    t = _Tree()
    data: dict = {}
    for m in _INT_LIST.finditer(block):
        key = m.group(1)
        body = m.group(2)
        if key in ("split_feature", "left_child", "right_child", "decision_type"):
            if key == "decision_type":
                continue  # 用默认 "<="；兼容老格式
            data[key] = [int(x) for x in body.split()]
        elif key == "threshold":
            data[key] = [float(x) for x in body.split()]
        elif key == "leaf_value":
            data[key] = [float(x) for x in body.split()]
        elif key == "num_leaves":
            t.num_leaves = int(body)

    # 缺失必需字段则拒绝
    if not (data.get("split_feature") and data.get("threshold")
            and data.get("leaf_value")):
        return None

    t.num_leaves = t.num_leaves or len(data["leaf_value"])
    t.split_feature = data["split_feature"]
    t.threshold = data["threshold"]
    t.leaf_value = data["leaf_value"]
    t.left_child = data.get("left_child", [])
    t.right_child = data.get("right_child", [])

    # 若无显式 child 数组，推断：内部节点 i 的左孩子 = 2i+1, 右孩子 = 2i+2
    # （LightGBM 的并行/紧凑格式以 -1 左、正右；这里统一处理负值即叶子）
    n_internal = max(len(t.split_feature), 0)
    if not t.left_child:
        t.left_child = [2 * i + 1 for i in range(n_internal)]
    if not t.right_child:
        t.right_child = [2 * i + 2 for i in range(n_internal)]
    return t


def load_ember_model(path: str) -> Optional[EMBERPredictor]:
    """从 LightGBM 模型文本加载；失败或校验不过返回 None。

    支持两种树头：标准 `Tree=N` 与旧式 `[Tree: N]`。
    多分类模型（num_class>1）一律拒绝 —— 本预测器只实现二分类，
    宁可"不加载"也不能给出错误的概率。
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        meta = _parse_header_meta(text)
        if meta["num_class"] > 1:
            return None

        blocks = _split_tree_blocks(text)
        if not blocks:
            return None

        trees = []
        for seg in blocks:
            t = _parse_tree_block(seg)
            if t is not None:
                trees.append(t)

        # 关键校验：每个树块都必须解析成功。少一棵就说明格式没吃透，
        # 此时返回半成品模型只会产出垃圾概率，不如直接拒绝。
        if not trees or len(trees) != len(blocks):
            return None

        return EMBERPredictor(trees, sigmoid=meta["sigmoid"])
    except Exception:
        return None


_MODEL_NAMES = (
    # 自训练 PE 模型的文本产物（tools/train_pe_model.py 输出）。
    # ⚠️ 原先漏了它：spec 不打包 onnxruntime，打包版靠这份文本模型回退，
    #    找不到就等于 ML 在交付物里完全没跑（2026-10-30 复查发现）。
    "pe_model.txt",
    "ember_model.txt", "ember.txt", "classifier.txt",
    "ember_2022.txt", "lightgbm_model.txt",
)


def _contract_lightgbm_file(base: str) -> Optional[str]:
    """按 features.json 契约里的 lightgbm_file 找文本模型（名字不写死）。"""
    try:
        import json
        cpath = os.path.join(base, "features.json")
        if not os.path.isfile(cpath):
            return None
        with open(cpath, "r", encoding="utf-8") as f:
            name = (json.load(f) or {}).get("lightgbm_file")
        if name:
            p = os.path.join(base, str(name))
            if os.path.isfile(p):
                return p
    except Exception:
        return None
    return None


def find_ember_model() -> Optional[str]:
    """在常见路径下查找模型文本文件；找不到返回 None。

    顺序：先读 features.json 契约的 lightgbm_file，再按 _MODEL_NAMES 兜底。
    """
    here = os.path.dirname(os.path.abspath(__file__))  # backend/engine
    roots = (
        os.path.join(here, "models"),
        os.path.join(here, ".."),
        os.path.join(here, "..", "models"),
        os.path.join(here, "..", "native"),
        os.path.join(here, "..", "..", "models"),
    )
    for root in roots:
        base = os.path.abspath(root)
        p = _contract_lightgbm_file(base)
        if p:
            return p
        for name in _MODEL_NAMES:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
    return None