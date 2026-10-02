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
    """解析并求值 EMBER 的 LightGBM 二分类模型（classifier.txt）。

    概率 = sigmoid( sum_over_trees( leaf_value ))。
    """

    def __init__(self, trees):
        self.trees = trees

    def predict_proba(self, features) -> float:
        """输入为 2381 维 EMBER v2 特征向量，返回恶意概率 0.0~1.0。"""
        raw = 0.0
        for tree in self.trees:
            raw += tree.eval(features)
        try:
            return 1.0 / (1.0 + math.exp(-raw))
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
_BLOCK_RE = re.compile(r"^\s*\[Tree:\s*(\d+)\]\s*$", re.MULTILINE)
_INT_LIST = re.compile(r"^\s*([A-Za-z_]+)=(.*)$", re.MULTILINE)


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
    """从 classifier.txt 加载模型；失败返回 None。"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        # 按 “[Tree: N]” 头切开，取每棵树的完整正文
        parts = re.split(r"(?m)^\s*\[Tree:\s*\d+\]\s*$", text)
        trees = []
        for seg in parts:
            seg = seg.strip()
            if "num_leaves" in seg:
                t = _parse_tree_block(seg)
                if t is not None:
                    trees.append(t)
        if not trees:
            return None
        return EMBERPredictor(trees)
    except Exception:
        return None


_MODEL_NAMES = (
    "ember_model.txt", "ember.txt", "classifier.txt",
    "ember_2022.txt", "lightgbm_model.txt",
)


def find_ember_model() -> Optional[str]:
    """在常见路径下查找 EMBER 模型文件；找不到返回 None。"""
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
        for name in _MODEL_NAMES:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
    return None