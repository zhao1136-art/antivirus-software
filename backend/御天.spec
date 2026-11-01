# -*- mode: python ; coding: utf-8 -*-

# ── 路径不再硬编码盘符 ──
# 原先 pathex 写死 'F:\Python314\Lib\site-packages'、datas 写死
# 'f:\Caelire\bingduku'。换机器或换盘符，打包直接失败。
# 2026-10-03：项目实际工作区在 H:\Caelire，而 F:\Caelire 是 8/28 的旧副本，
# 所有构建脚本却都 cd 到 F 盘 —— 等于一直在打包旧代码。这里改成从
# spec 自身位置和当前解释器推导，走到哪台机器都对。
import os as _os
import sys as _sys
# ⚠️ PyInstaller 执行 spec 时**没有 __file__**（实测 NameError: name '__file__'
#    is not defined）。用它注入的 SPECPATH；再兜底到 CWD（构建脚本都会先 cd 到
#    backend 目录）。这个坑只有真跑一次打包才会暴露。
_ROOT = globals().get('SPECPATH') or _os.getcwd()
_SITE = _os.path.join(_os.path.dirname(_sys.executable), 'Lib', 'site-packages')

# ── binaries: 原生二进制 ──
# engine/native/native_engine.exe（破军引擎，子进程模式）。
# 原生对抗层 native_guard.dll / file_guard.exe / amsi_provider.dll 由下方
# datas 的 ('engine','engine') 递归打包进 engine/native_guard/ 目录。
import glob as _glob
_binaries = [('engine/native/native_engine.exe', 'engine/native')]

# libs/*.libs/*.dll —— vendored numpy/scipy/pandas 伴随的 OpenBLAS 等原生依赖。
# 踩过的坑：项目实际使用的是 libs/numpy（2.5.1），而 PyInstaller 的 numpy 钩子
# 只从被解析到的 site-packages 取 numpy.libs，二者 OpenBLAS 文件名哈希不同
# （b788… vs 63c8…）。结果是 numpy 的 pyd 被收集进包、运行时却因 DLL 找不到而
# 加载失败 —— 打出「看着成功、跑起来 numpy 报错」的坏包。这里显式收集一份。
for _dll in _glob.glob(_os.path.join(_ROOT, 'libs', '*.libs', '*.dll')):
    _binaries.append((_dll, _os.path.basename(_os.path.dirname(_dll))))

# ── libyara.dll（真 YARA 引擎）──
# 2026-10-05：YARA 引擎从"自制子集"换成自建的 libyara.dll（YARA 4.5.5，
# 构建配方见 engine/native/yara/BUILD.md）。该 DLL 随下方 datas 的
# ('engine','engine') 递归打包到 _internal/engine/native/yara/，
# 与 native_guard 的 amsi_provider.dll 同一机制，无需单独列 binaries。
#
# 但**必须显式断言它在**：若哪天 datas 改成显式文件列表而漏了它，
# 打包会"看着成功"，运行时 engine/yara_scanner.py 的 _load_lib() 找不到 DLL
# 会抛 RuntimeError，而 Scheduler.__init__ 直接构造 YaraScanner(无 try/except)
# —— 那是启动即失败（loud），不会静默失去 YARA 检测。宁可打包期就报错。
_libyara = _os.path.join(_ROOT, 'engine', 'native', 'yara', 'libyara.dll')
if not _os.path.isfile(_libyara):
    raise SystemExit(
        '打包中止：缺少真 YARA 引擎 %s\n'
        '请按 engine/native/yara/BUILD.md 重新构建，或从备份恢复。' % _libyara)

# ── 界面：ui_tk/（Tkinter）──
# 主界面已从 HTML+WebView2 换成 ui_tk/ 下的 Tkinter 实现（见 app.py 顶部说明）。
# app.py 冻结态在 sys._MEIPASS/ui_tk 下找 run_ui.py，找到后把它加进 sys.path，
# 再 `from andun_ui.app import App` —— 所以 ui_tk 必须**作为数据原样拷进去**，
# 且不能漏 andun_ui/ 下的页面模块，否则打包版会以
# 「找不到 ui_tk 界面目录（需含 run_ui.py）」直接 sys.exit(2)。
#
# ui_tk 在仓库根，不在 backend 下：SPECPATH 是 backend，上级目录才是仓库根。
_UI_TK = _os.path.join(_os.path.dirname(_ROOT), 'ui_tk')
if not _os.path.isfile(_os.path.join(_UI_TK, 'run_ui.py')):
    raise SystemExit(
        '打包中止：缺少新界面目录 %s（需含 run_ui.py）\n'
        '主界面依赖它，缺了打包版起不来。' % _UI_TK)

# 只收 .py，跳过 __pycache__ —— 否则会把过期 .pyc 一起打进去。
_UI_TK_DATAS = []
for _dp, _dn, _fn in _os.walk(_UI_TK):
    _dn[:] = [d for d in _dn if d != '__pycache__']
    _rel = _os.path.relpath(_dp, _UI_TK)
    _dest = 'ui_tk' if _rel == '.' else _os.path.join('ui_tk', _rel)
    for _f in _fn:
        if _f.endswith('.py'):
            _UI_TK_DATAS.append((_os.path.join(_dp, _f), _dest))

a = Analysis(
    ['app.py'],
    pathex=['libs', _SITE],
    binaries=_binaries,
    datas=[('frontend', 'frontend'), ('engine', 'engine'), ('config.py', '.'),
           ('database', 'database'), ('御天图标.ico', '.'),
           ('persistence.py', '.'),
           # 第三方许可与源码获取声明必须**随包分发**（GPL-2.0 的义务）：
           # ClamAV 1.5.3 以独立子进程调用，但仍是分发 GPL 程序，
           # 需附 GPL 全文 + 书面源码要约。见 licenses/THIRD_PARTY_LICENSES.md。
           ('licenses', 'licenses'),
           ('engine_loader.py', '.'), ('amsi_manager.py', '.')]
          + _UI_TK_DATAS,
    # 原先是 ('f:\\Caelire\\bingduku', 'bingduku') —— 已移除，两个原因：
    #   1) 硬编码盘符，换机器打包直接失败；
    #   2) F:\Caelire\bingduku 实测是**空目录**（0 个文件），本来也没打进任何东西。
    # 病毒库的真实来源见 engine/signature_downloader.py 与 data/ 下的库文件。
    hiddenimports=[
        # 内嵌 WebView2 链路（pywebview / pythonnet / clr_loader / bottle /
        # proxy_tools）已随界面换成 ui_tk/ 从 app.py 删除，这里不再收集。
        # 注意：这些包在本机是装着的，继续收集不会报错，只会把 .NET 运行时和
        # WebView2 相关 DLL 白打进包里 —— 属于"看着没事"的体积浪费。
        'cffi', 'pycparser',
        # ── 新界面（ui_tk/）的依赖 ──
        # ui_tk 是当 datas 拷进去的，PyInstaller **不做静态分析**，它用了哪些
        # 标准库模块打包器一无所知。所以这里显式列出：这些模块若哪天缺失，
        # 打包版会在 `from andun_ui.app import App` 处直接崩，而不是打包期报错。
        'tkinter', 'tkinter.font', 'tkinter.filedialog', 'tkinter.messagebox',
        'tkinter.ttk', 'tkinter.scrolledtext',
        'lzma',
        'capa', 'capa.main', 'capa.engine', 'capa.loader', 'capa.rules',
        'capa.render', 'capa.render.json', 'capa.features',
        'capa.capabilities', 'capa.helpers', 'capa.exceptions',
        # ⚠️ 不要加 'lightgbm'：项目运行时**没有任何代码 import 它**
        #    （EMBER 推理走 engine/ember_model.py 的纯 Python 实现），
        #    而下方 excludes 里明确排除了 scipy。lightgbm 强依赖 scipy，
        #    收进来只会得到一个 "import 就报缺 scipy" 的坏模块 + 白增体积。
        'numpy', 'lief',
        'oletools', 'pdfminer', 'psutil', 'tqdm', 'pefile',
        'asyncio', 'concurrent.futures', 'multiprocessing',
        'json', 'hashlib', 'base64', 'sqlite3',
        'email.mime.text', 'email.mime.multipart',
        'engine.startup_scanner', 'engine.network_monitor',
        'engine.policy_manager', 'engine.integrity',
        'engine.file_guard_client',
        'engine.history_manager',
        'engine.native_bridge',
        'engine.dex_parser',
        'engine.emergency_kill',
        'engine.realtime_guard',
        # EMBER 纯 Python LightGBM 推理（p13 接入，惰性 import 需显式收集）
        'engine.ember_model', 'engine.ml_scanner',
        # ONNX 推理器。⚠️ **不要把 'onnxruntime' 列进 hiddenimports**：
        # 2026-10-25 实测，PyInstaller 的隔离子进程在 import onnxruntime 时直接崩溃
        #   SubprocessDiedError: Child process died calling import_library()
        #   Isolated subprocess crashed while importing package 'onnxruntime'!
        # 导致整个打包失败。而 ONNX 只是**可选加速**：engine/ember_onnx.py 里
        # onnxruntime 是惰性 import，缺失时 load_onnx_model() 返回 None，
        # ml_scanner._get_ember_predictor() 会自动退回 LightGBM 文本模型
        # （engine/ember_model.py 的纯 Python 评估器，实测 1~3ms/次）。
        # 所以包里只放 pe_model.txt + features.json，不放 onnxruntime。
        'engine.ember_onnx',
        'engine.ransomware_shield',
        'engine.network_repair', 'engine.adblock',
        'engine.download_guard', 'engine.process_guard',
        'engine.registry_guard', 'engine.behavior_block',
        'engine.shell_integration', 'engine.auto_start',
        'engine.usb_scanner', 'engine.game_mode',
        'engine.tray_icon', 'engine.native_guard_bridge',
        # 懒加载企业级安全模块（PyInstaller 无法通过静态分析发现）
        'engine.anti_rootkit', 'engine.custom_rules', 'engine.honeypot_manager',
        'engine.browser_guard', 'engine.camera_guard', 'engine.privacy_shield',
        'engine.data_recovery', 'engine.sandbox',
        'engine.self_protect', 'engine.response_center',
        # 云查杀 + 特征库增量下载模块
        'engine.cloud_scanner', 'engine.signature_downloader',
        # AVIC 云查杀客户端 SDK
        'engine.avic_client',
        # AlienVault OTX 云查杀客户端 SDK
        'engine.otx_client',
        # 病毒检测系统弹窗通知
        'engine.notification',
        # ── 2026-10-03 新增模块（本轮改造的产物）──
        # 这些模块都是**函数内惰性 import**（包在 try/except 里做降级），
        # PyInstaller 的静态分析对它们不可靠。虽然 datas 的 ('engine','engine')
        # 会把整个目录当数据拷进去、暂时 import 得到，但那是脆的 ——
        # 哪天 datas 改成显式文件列表，这几个就会**静默消失**。
        # 所以显式列出来，别依赖目录递归兜底。
        'engine.heuristic_engine',   # 启发式引擎（从 local_scanner/url_guard 抽出）
        'engine.rule_quality',       # YARA 规则置信度分级（闸门零的依据）
        'engine.huorong_intel',      # 火绒情报库（内容特征串/恶意网址/检测名/哈希存档）
        'engine.threat_decision',    # 威胁处置：系统文件复核 + 用户决定队列
        'engine.memory_scanner',     # 进程内存镜像扫描（抓加壳/注入）
        'engine.desktop_prompt',     # 桌面决策窗口（tkinter，用户不在浏览器前时的唯一可点通道）
        'engine.isolation',          # 可插拔沙箱隔离引擎包
        'engine.isolation.base',
        'engine.isolation.copy_engine',
        'engine.isolation.none_engine',
        # 注意：engine.desktop_prompt 用 tkinter，而 tkinter 之所以会被打进去，
        # 是因为入口 app.py 里有 import tkinter（约 2812 行）被静态分析扫到。
        # 哪天 app.py 那段被删掉，桌面决策窗口就会**静默失效** —— 别删。
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # ===== pywin32 相关：**必须排除**（2026-10-31 更正）=====
    # 审查曾建议"别排除 pythoncom/win32com，否则 USB 监控/启动项扫描会静默失效"。
    # 实测核查后该判断不成立：
    #   1) 本机**根本没装 pywin32**（site-packages 只有 pywin32_ctypes 存根），
    #      import pythoncom / win32com 在开发模式和打包版里**都**失败；
    #   2) 两条使用路径都有无依赖回退，实测可用：
    #        engine/usb_scanner.py:_monitor_loop   → import 失败则走 _poll_monitor() 轮询
    #        engine/startup_scanner.py:_resolve_shortcut → 失败则手工解析 .lnk 二进制
    #   3) 反过来，把它们从 excludes 去掉会让 PyInstaller 的 pywin32 钩子在隔离子进程里
    #      `get_module_attribute('pythoncom','__file__')` 直接崩，构建 1.6 分钟就失败：
    #        ModuleNotFoundError: No module named 'pywintypes'
    #        AttributeError: Failed to retrieve attribute __file__ from module pythoncom
    # 所以这里继续排除，并保留注释说明原因，避免以后又被人"修复"一遍。
    excludes=['pythoncom', 'pywintypes', 'win32api', 'win32com', 'win32ui',
              'win32event', 'win32file', 'win32pipe', 'win32process',
              'win32security', 'win32service', 'win32clipboard',
              'scipy', 'sklearn', 'pandas', 'matplotlib',
              # ── 深度学习栈：本项目**没有任何代码 import torch**（已 grep 确认），
              #    但 PyInstaller 会把它卷进依赖图：实测日志里 torch 出现 111 次，
              #    不仅让构建臃肿、还把隔离子进程撑到崩溃。
              #    排除后包体积和构建时间都会明显下降。
              'torch', 'torchvision', 'torchaudio', 'tensorboard',
              'tensorflow', 'transformers', 'onnx', 'onnxruntime'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='御天',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_os.path.join(_ROOT, '御天图标.ico'),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='御天',
)