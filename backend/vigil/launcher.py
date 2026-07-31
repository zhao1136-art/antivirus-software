"""
安盾 Vigil 强力模式启动器
在后台启动 Vigil Flask 仪表盘 (端口 7331)
"""
import sys, os, threading

VIGIL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, VIGIL_DIR)
sys.path.insert(0, os.path.join(VIGIL_DIR, "src"))

_ready = threading.Event()

def start_dashboard(host="127.0.0.1", port=7331):
    """后台启动 Vigil 仪表盘，返回 threading.Thread"""
    _ready.clear()  # 重置事件，支持重复调用
    def _run():
        try:
            from dashboard import app as vigil_app
            # 确保必要目录存在
            for d in ["logs", "quarantine", "restored", "models"]:
                dp = os.path.join(VIGIL_DIR, d)
                os.makedirs(dp, exist_ok=True)
            # 检查模型文件
            pe_model = os.path.join(VIGIL_DIR, "models", "model.lgbm")
            ps1_model = os.path.join(VIGIL_DIR, "models", "ps1_model.lgbm")
            if os.path.isfile(pe_model):
                print(f"[Vigil] PE 模型已加载: {pe_model}")
            else:
                print(f"[Vigil] 警告: PE 模型不存在 ({pe_model})，PE 扫描将不可用")
            if os.path.isfile(ps1_model):
                print(f"[Vigil] PS1 模型已加载: {ps1_model}")
            else:
                print(f"[Vigil] 提示: PS1 模型不存在，PowerShell 扫描将不可用")
            # 检查依赖是否就绪
            try:
                import numpy, lightgbm, sklearn
                print("[Vigil] 核心 ML 依赖已就绪")
            except ImportError as e:
                print(f"[Vigil] 警告: ML 依赖缺失 ({e})，扫描功能受限")
            _ready.set()
            print(f"[Vigil] Dashboard starting on http://{host}:{port}")
            vigil_app.run(host=host, port=port, debug=False, use_reloader=False)
        except Exception as e:
            import traceback
            print(f"[Vigil] Failed to start: {e}")
            traceback.print_exc()
            _ready.set()
    
    t = threading.Thread(target=_run, daemon=True, name="vigil-dashboard")
    t.start()
    _ready.wait(timeout=10)
    return t

if __name__ == "__main__":
    start_dashboard()
    import time
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Vigil] Stopped")
