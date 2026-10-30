"""ONNX 版 PE 机器学习推理器 —— 带 features.json 契约校验。

为什么单独做一层
----------------
`ember_model.py` 是**纯 Python 的 LightGBM 文本模型评估器**（没有 onnxruntime
也能跑，但每棵树都要走一遍解释循环）。ONNX 走原生内核，实测单次推理
0.046ms（约 2 万次/秒），比纯 Python 评估快两个数量级，且模型体积更小。

两种模型的加载优先级见 `ml_scanner._get_ember_predictor()`：
ONNX 优先，缺失时退回 LightGBM 文本模型。

features.json 契约（借鉴 PYAS 的做法，这层是防"静默失效"的关键）
----------------------------------------------------------------
模型目录里必须同时有 `features.json`，记录：
  · `dim`              —— 特征维数；加载时与 ONNX 输入 `shape[1]` **硬校验**
  · `feature_order`    —— 特征顺序，长度必须等于 dim
  · `extractor_sha256` —— 特征提取器源码指纹；不匹配只告警（可能是换了版本），
                          但这正是"模型与特征器错配"最隐蔽的一种失效
  · `onnx`             —— 输入/输出张量名，避免写死；LightGBM 转换出来的模型
                          有 label/probabilities 两个输出，取错那个会得到
                          「全是 0/1 的标签」而不是概率

缺契约文件时**拒绝加载** —— 宁可没有 ML，也不要拿错维度的向量去推理
（那会返回一个看起来正常、实际毫无意义的概率）。
"""
from __future__ import annotations

import hashlib
import json
import os

__all__ = ["MODELS_DIR", "find_model_files", "load_onnx_model", "OnnxPredictor",
           "load_contract"]

# 模型目录：与 engine/ 同级，随 ('engine','engine') 打进包里
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

_LOG_PREFIX = "[ML-ONNX]"


def _log(msg: str):
    try:
        print(f"{_LOG_PREFIX} {msg}")
    except Exception:
        pass


def _extractor_fingerprint() -> str:
    """特征提取器源码指纹（engine/ml_scanner.py）—— 仅作信息记录。"""
    try:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml_scanner.py")
        with open(p, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


# 固定合成输入：覆盖全部 256 个字节值、足够长以走滑动窗口分支。
# 非 PE（没有 MZ），但 histogram / byteentropy / strings 三个分支都会算到。
_PROBE_BYTES = bytes(range(256)) * 64


def extractor_probe_vector() -> list[float] | None:
    """**行为指纹**：在固定输入上算一遍特征向量。

    为什么不用源文件哈希：源文件哈希对任何改动都敏感 —— 改注释、加一行导入、
    接一个调用，都会让"提取器变了"误报。而这里比对的是**实际算出来的特征值**：
    重构和无关改动不影响，真正改变特征语义（哪怕只动一个 bin 边界）一定不同。
    """
    try:
        from engine.ml_scanner import PEFeatureExtractor
        fv = PEFeatureExtractor().feature_vector(_PROBE_BYTES)
        return [round(float(v), 6) for v in fv]
    except Exception:
        return None


def _probe_matches(contract_probe) -> bool | None:
    """契约里的行为指纹是否与当前提取器一致；契约没存返回 None。"""
    if not contract_probe:
        return None
    now = extractor_probe_vector()
    if not now or len(now) != len(contract_probe):
        return False
    try:
        worst = max(abs(float(a) - float(b)) for a, b in zip(now, contract_probe))
    except (TypeError, ValueError):
        return False
    return worst <= 1e-6


def find_model_files(models_dir: str | None = None):
    """返回 (onnx 路径, features.json 路径)；两者必须都存在，否则 None。"""
    d = models_dir or MODELS_DIR
    try:
        names = os.listdir(d)
    except OSError:
        return None
    contract = os.path.join(d, "features.json")
    if not os.path.isfile(contract):
        return None
    try:
        with open(contract, "r", encoding="utf-8") as f:
            c = json.load(f)
    except Exception as exc:
        _log(f"features.json 解析失败: {exc}")
        return None
    onnx_name = (c.get("onnx") or {}).get("model_file") or c.get("model_file") \
        or "pe_model.onnx"
    onnx_path = os.path.join(d, onnx_name)
    if not os.path.isfile(onnx_path):
        # 兜底：目录里唯一的 .onnx
        cand = [n for n in names if n.lower().endswith(".onnx")]
        if len(cand) == 1:
            onnx_path = os.path.join(d, cand[0])
        else:
            return None
    return onnx_path, contract


def load_contract(contract_path: str | None = None) -> dict | None:
    """读取并做静态校验（不加载模型）。供 API/界面展示模型信息。"""
    if contract_path is None:
        got = find_model_files()
        if not got:
            return None
        contract_path = got[1]
    try:
        with open(contract_path, "r", encoding="utf-8") as f:
            c = json.load(f)
    except Exception:
        return None
    dim = c.get("dim")
    order = c.get("feature_order") or []
    if not isinstance(dim, int) or dim <= 0:
        return None
    if order and len(order) != dim:
        _log(f"契约不一致：dim={dim} 但 feature_order 长度={len(order)}")
        return None
    fp_now = _extractor_fingerprint()
    c["_extractor_source"] = bool(c.get("extractor_sha256")) and \
        c.get("extractor_sha256") == fp_now
    # 行为指纹优先（精确且不误报）；契约没存时退回源码哈希
    probe_ok = _probe_matches(c.get("extractor_probe"))
    if probe_ok is None:
        c["_extractor_match"] = c["_extractor_source"]
        c["_match_method"] = "source-hash"
    else:
        c["_extractor_match"] = probe_ok
        c["_match_method"] = "behavioral-probe"
    return c


def _allow_stale_ml() -> bool:
    """是否允许加载"特征器已变、模型未重训"的模型 —— **默认不允许**。

    为什么默认拒绝：模型与特征器错配是这类 ML **最隐蔽的失效方式**。
    ONNX 照常返回一个 0~1 的概率、日志照常写 `ml_status=ok`，但那个概率
    与文件是否恶意已经无关 —— 比"没有 ML"更危险。
    调试/回滚场景可临时放宽：环境变量 ANDUN_ALLOW_STALE_ML=1。
    """
    return os.environ.get("ANDUN_ALLOW_STALE_ML", "").strip().lower() in ("1", "true", "yes")


class OnnxPredictor:
    """ONNX Runtime 推理器；`predict_proba(list) -> float`（恶意概率）。"""

    def __init__(self, onnx_path: str, contract: dict):
        import onnxruntime as ort  # 延迟导入：没装 onnxruntime 时整条链路安全跳过

        self.model_path = onnx_path
        self.contract = contract
        self.dim = int(contract["dim"])
        self.io = contract.get("onnx") or {}
        self._input_name = self.io.get("input") or "input"
        self._output_name = self.io.get("output") or "probabilities"
        # positive_index：正类（恶意）在输出概率矩阵里的列号
        self._positive_index = int(self.io.get("positive_index", 1))

        opts = ort.SessionOptions()
        opts.log_severity_level = 3          # 只报错，压掉 shape 告警
        self.sess = ort.InferenceSession(
            onnx_path, sess_options=opts, providers=["CPUExecutionProvider"])

        # —— 硬校验：契约维数必须与模型输入维数一致 ——
        inputs = self.sess.get_inputs()
        if not inputs:
            raise ValueError("ONNX 模型没有输入")
        shape = inputs[0].shape
        if len(shape) != 2 or shape[1] is None:
            raise ValueError(f"ONNX 输入形状异常: {shape}")
        if int(shape[1]) != self.dim:
            raise ValueError(
                f"维数不一致：模型期望 {shape[1]}，契约声明 {self.dim}"
                "（特征提取器与模型不匹配，拒绝加载）")
        self._input_shape = shape
        self._output_names = [o.name for o in self.sess.get_outputs()]
        if self._output_name not in self._output_names:
            raise ValueError(f"契约指定的输出 {self._output_name!r} 不在模型输出 "
                             f"{self._output_names} 中")

        if not contract.get("_extractor_match", True):
            _log("警告：特征提取器源码指纹与训练时不一致 —— 模型可能已过期，"
                 "输出不可信（请重训或回退旧提取器）")
        # 分析长度口径校验：训练截断长度与运行时不同 → 特征分布偏移（同一文件
        # 两边会被截成不同长度）。不致命，但必须让人看见。
        try:
            _train_cap = contract.get("analysis_max_bytes")
            from config import ML_ANALYSIS_MAX_BYTES as _rt_cap
            if _train_cap and int(_train_cap) != int(_rt_cap):
                _log(f"警告：训练时分析上限 {int(_train_cap)} 字节 ≠ 运行时 "
                     f"{int(_rt_cap)} 字节 —— 特征分布会偏移，建议重训或统一配置")
        except Exception:
            pass
        _log(f"已加载 ONNX 模型 {os.path.basename(onnx_path)} "
             f"dim={self.dim} 训练于 {contract.get('trained_at', '?')}")

    # ── 推理 ──
    def predict_proba(self, features) -> float:
        """输入 2381 维特征，返回恶意概率（0~1）。"""
        import numpy as np
        arr = np.asarray(features, dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.shape[1] != self.dim:
            raise ValueError(f"特征维数 {arr.shape[1]} != 模型 {self.dim}")
        out = self.sess.run([self._output_name], {self._input_name: arr})[0]
        data = np.asarray(out)
        if data.ndim == 2:
            return float(data[0, self._positive_index])
        return float(data.ravel()[0])

    # ── 供界面展示 ──
    def info(self) -> dict:
        c = self.contract
        hold = c.get("holdout") or {}
        return {
            "backend": "onnx",
            "model": os.path.basename(self.model_path),
            "dim": self.dim,
            "trained_at": c.get("trained_at"),
            "auc": hold.get("auc"),
            "fpr": hold.get("fpr"),
            "recall": hold.get("recall"),
            "extractor_match": bool(c.get("_extractor_match", True)),
            "note": c.get("note"),
        }


def load_onnx_model(models_dir: str | None = None) -> OnnxPredictor | None:
    """加载 ONNX 模型；任何异常都返回 None（调用方退回 LightGBM 或不跑 ML）。

    特征器指纹不匹配时**拒绝加载**（除非 ANDUN_ALLOW_STALE_ML=1）：
    宁可退回 LightGBM 文本模型或干脆不跑 ML，也不返回一个与文件无关的概率。
    """
    got = find_model_files(models_dir)
    if not got:
        return None
    onnx_path, contract_path = got
    contract = load_contract(contract_path)
    if contract is None:
        _log("features.json 无效，拒绝加载 ONNX 模型")
        return None
    if not contract.get("_extractor_match", True):
        if _allow_stale_ml():
            _log("⚠️ 特征提取器指纹与训练时不一致，但仍按 ANDUN_ALLOW_STALE_ML=1 加载"
                 "（输出概率不可信，仅供调试）")
        else:
            _log("拒绝加载 ONNX 模型：特征提取器指纹与训练时不一致。"
                 "输出概率会与文件实际是否恶意无关 —— 请重训模型"
                 "（tools/train_pe_model.py），或临时设 ANDUN_ALLOW_STALE_ML=1")
            return None
    try:
        return OnnxPredictor(onnx_path, contract)
    except ImportError:
        _log("未安装 onnxruntime，跳过 ONNX 模型")
        return None
    except Exception as exc:
        _log(f"ONNX 模型加载失败: {type(exc).__name__}: {exc}")
        return None
