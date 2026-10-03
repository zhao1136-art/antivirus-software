"""
御天实时防护（新版）启动器

独立进程启动用，避免依赖 PYTHONPATH（本机 Python 是隔离部署，
PYTHONPATH 与 CWD 都不进 sys.path）：

    python run_rtguard.py --level low --ui-port 8022
    python run_rtguard.py --once "D:\\samples"
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rtguard.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
