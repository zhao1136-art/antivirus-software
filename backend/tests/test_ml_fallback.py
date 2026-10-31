"""PE 机器学习模型的回退链路测试。

背景（2026-10-30 复查）：打包版 spec 明确不打包 onnxruntime，靠纯 Python
LightGBM 文本模型回退；但 `find_ember_model()` 曾不认识训练产物
`pe_model.txt` → 交付物 `ml_status` 恒为 no_model，三个 ML 提交全部无效。
这里把“找得到文本模型 / 没有 onnxruntime 也能拿到 predictor / 首加载并发安全”
钉成回归测试。
"""
import os
import sys
import threading

import pytest


def _ml():
    import engine.ml_scanner as ml
    return ml


def test_find_ember_model_finds_trained_text_model():
    from engine.ember_model import find_ember_model, load_ember_model
    path = find_ember_model()
    assert path, "找不到模型文本文件（pe_model.txt / ember_model.txt 等）"
    assert load_ember_model(path) is not None


def test_contract_lightgbm_file_is_used():
    """features.json 契约里的 lightgbm_file 必须能被解析使用。"""
    import json
    from engine.ember_model import _contract_lightgbm_file
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "engine", "models")
    contract = os.path.join(models_dir, "features.json")
    if not os.path.isfile(contract):
        pytest.skip("没有 features.json 契约")
    with open(contract, "r", encoding="utf-8") as f:
        name = json.load(f).get("lightgbm_file")
    if not name or not os.path.isfile(os.path.join(models_dir, name)):
        pytest.skip("契约未声明/缺 lightgbm_file")
    assert os.path.basename(_contract_lightgbm_file(models_dir)) == os.path.basename(name)


def test_predictor_available_without_onnxruntime(monkeypatch):
    """模拟打包版：onnxruntime 不可用时也必须拿到文本模型 predictor。"""
    ml = _ml()
    monkeypatch.setitem(sys.modules, "onnxruntime", None)
    ml._EMBER_PREDICTOR_CACHE = None
    ml._EMBER_PREDICTOR_LOADED = False
    pred = ml._get_ember_predictor()
    assert pred is not None, "没有 onnxruntime 时回退模型为空（打包版 ML 会全灭）"
    assert hasattr(pred, "predict_proba")


def test_predictor_first_load_is_thread_safe():
    """4 线程同时首加载，不应有线程拿到 None（原先实测 3/4 拿到 None）。"""
    ml = _ml()
    ml._EMBER_PREDICTOR_CACHE = None
    ml._EMBER_PREDICTOR_LOADED = False
    n = 4
    barrier = threading.Barrier(n)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        pred = ml._get_ember_predictor()
        with lock:
            results.append(pred)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert len(results) == n, "有线程没有返回（死锁？）"
    assert all(p is not None for p in results), "并发首加载有线程拿到 None: %r" % (results,)
