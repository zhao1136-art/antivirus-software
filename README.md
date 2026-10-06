# 御天（安盾）安全防护系统

基于 Python 的全栈安全防护软件，集成本地病毒查杀、云查杀、实时防护、垃圾清理、系统优化等多层安全引擎。

> **文档同步状态**：本 README 已于 2026-10-05 按仓库实际内容重写。
> 此前版本描述的内核驱动（`andun.sys`）、防火墙（`firewall.py`）、HIPS（`hips.py`）、
> 内核桥接（`kernel_bridge.py`）**已在提交 `adf8581` 整体移除**，相关章节已删除。
> 仍待处理的问题见 [`ISSUES.md`](ISSUES.md)。

---

## 项目结构

```
H:\Caelire\
├── README.md                       # 本文件
├── ISSUES.md                       # 待办问题清单（含驱动移除遗留项、已知缺陷）
├── 发布说明_御天抢先版.md            # v1.0.1 发布说明（2026-08-25）
│
├── backend/                        # ★ 后端服务（FastAPI 主程序）
│   ├── app.py                      # 主入口：FastAPI API 网关 + WebSocket 进度推送
│   ├── config.py                   # 应用配置（开发/打包双模式路径、持久化覆盖）
│   ├── persistence.py              # 持久化存储（配置、守护天数、扫描缓存 DB）
│   ├── engine_loader.py            # 引擎模块动态加载器
│   ├── amsi_manager.py             # AMSI Provider 注册/注销/校验
│   ├── file_integrity_checker.py   # 文件完整性校验
│   ├── frontend_launcher.py        # 内置窗口（pywebview）启动
│   ├── logo_splash.py              # 启动 Logo 淡入淡出
│   │
│   ├── 启动安盾.bat                # 开发模式启动脚本
│   ├── 打包御天.cmd / pack*.bat     # 打包脚本集
│   ├── requirements.txt            # Python 依赖（6 项）
│   ├── 御天.spec                   # PyInstaller onefile 打包 spec
│   ├── 御天_onedir.spec            # PyInstaller onedir 打包 spec（当前发布用）
│   ├── Dockerfile / docker-compose.yml
│   │
│   ├── engine/                     # ★ 核心检测引擎（74 个 Python 模块）
│   ├── frontend/                   # 前端页面（16 个 HTML + 2 个 JS）
│   ├── native/                     # C/C++ 破军引擎源码 + 编译产物 + ClamAV 运行库
│   ├── native_guard/               # C++ 原生防护层（AMSI / ETW / 注入 / 无文件 / 持久化）
│   ├── yara_rules/                 # YARA 规则集（114 个 .yar）
│   ├── capa_rules/                 # capa 行为规则（约 1069 条）
│   ├── huorong_data/               # 火绒特征数据（参考资料）
│   ├── data/                       # 开发模式运行时数据（db/ logs/ quarantine/）
│   ├── database/                   # schema.sql + vulnerabilities.db + virus_memory.db
│   ├── tests/                      # 测试（6 个文件 / 569 行）
│   ├── libs/                       # 内置第三方库（cp314，已 gitignore）
│   ├── p2p_tunnel/                 # P2P 隧道模块（STUN / NAT 探测 / TCP 打洞）
│   ├── driver/                     # （已移除，见 ISSUES.md 1.6）
│   └── _tmp/                       # 构建中间产物（yara / openssl / pcre2 等）
│
├── installer/                      # 安装/卸载程序
│   ├── installer.py                # 安装程序
│   ├── uninstaller.py              # 卸载程序
│   ├── installer_common.py         # 安装公共模块
│   ├── build_installer.py          # 构建脚本
│   ├── installer.spec / uninstaller.spec
│   └── cleanup.bat                 # 旧版驱动残留清理（有意保留）
│
├── rtguard/                        # ★ 实时防护重写版（独立进程，零第三方依赖）
│   ├── README.md                   # 架构说明与性能对比
│   ├── run_rtguard.py              # 入口
│   ├── rtguard/                    # matcher / scanner / watcher / throttle / tray / ui
│   └── native/                     # Aho-Corasick 原生匹配器（matcher.c → matcher.dll）
│
├── data/                           # 根级运行数据（scan_cache.db / config_save.json / guard_days.json）
├── deploy-config/                  # 部署配置（ssh 密钥 + server.env）
│
├── ai_learning_results/            # AI 自动学习记录（含 index.md 索引）
├── yara-daily/                     # YARA 规则每日更新
├── huorong_extract/                # 火绒特征提取结果
│
│  ── 第三方参考源码（仅供比对，不参与打包）──
├── Yara-rules-master/              # YARA 规则集
├── yarGen-master/                  # YARA 规则生成器
├── capa-master/                    # capa 行为分析
├── ember-master/                   # EMBER 数据集 / MalConv 模型
├── maltrail-master/                # 恶意流量检测
├── pe-sieve-master/                # PE-sieve 进程扫描
├── libpeconv-master/               # libpeconv PE 处理库
├── C2IntelFeeds-master/            # C2 情报源
├── clamav-main/                    # ClamAV 源码
└── clamav-1.5.3.win.x64/           # ClamAV Windows x64 发行版
```

> **说明**：以下条目存在于旧版 README 但仓库中已不存在，故删除——
> `firewall.py`、`hips.py`、`kernel_bridge.py`、`firewall.html`、`backend/driver/`、
> `bingduku/`、`release/`、`deploy-staging/`、`test_samples/`、根级 `启动安盾.bat`（实际在 `backend/`）。

---

## 代码规模

来源：`ISSUES.md`（2026-10-02 统计，删驱动后）

| 范围 | 文件数 | 行数 |
|------|--------|------|
| 自有 Python（`backend` 不含 `libs` + `installer`） | 144 | 46,571 |
| 自有 C/C++（原生层） | 20 | 7,667 |
| `backend/tests` | 6 | 569 |
| `backend/libs`（内置第三方，已 gitignore） | 4,704 | 2,239,743 |

---

## 核心引擎模块（`backend/engine/`）

### 扫描与检测

| 模块 | 文件 | 功能描述 |
|------|------|----------|
| 本地扫描 | `local_scanner.py` | 本地病毒查杀，支持 Windows PE 和 Android APK 检测 |
| 特征库 | `signature_manager.py` | 病毒特征库管理，SQLite 存储，批量导入 |
| 特征更新 | `signature_downloader.py` | 多源威胁情报下载与幂等导入 |
| YARA 扫描 | `yara_scanner.py` | 基于 YARA 规则的恶意代码匹配 |
| 机器学习 | `ml_scanner.py` | 基于 ML 模型的可疑文件分类 |
| 模型封装 | `ember_model.py` | MalConv / EMBER 模型独立实现（不 import ember） |
| 云查杀 | `cloud_scanner.py` | 多引擎云查杀编排（AVIC / 微步 / OTX） |
| 深度分析 | `deep_analyzer.py` | 多引擎深度扫描 |
| 启发式 | `heuristic_engine.py` | 7 维启发式打分 |
| 沙箱 | `sandbox.py` | 可疑文件沙箱隔离分析 |
| DEX 解析 | `dex_parser.py` | Android DEX 字节码解析 |
| 威胁判定 | `threat_decision.py` | 系统文件二次复核 + 用户决定闸门 |
| 规则质量 | `rule_quality.py` | 规则误报率评估 |

### 实时防护

| 模块 | 文件 | 功能描述 |
|------|------|----------|
| 实时文件监控 | `realtime_guard.py` | `ReadDirectoryChangesW` 目录监控 → 防抖 → 扫描 → 隔离 |
| 文件防篡改 | `file_guard.py` | 关键系统文件 SHA256 基线与完整性校验 |
| 进程防护 | `process_guard.py` | 关键进程监控，检测注入与伪装 |
| 系统防护 | `system_guard.py` | 系统关键资源保护与基线 |
| 注册表防护 | `registry_guard.py` | 注册表写入/删除监控与自动还原 |
| 勒索防护 | `ransomware_shield.py` | 勒索软件行为检测与阻断 |
| 行为阻断 | `behavior_block.py` | 高危行为阻断 |
| 下载防护 | `download_guard.py` | 下载目录监控 |
| 网址防护 | `url_guard.py` | URL 黑白名单与 hosts 同步 |
| 邮件防护 | `mail_guard.py` | 邮件正文/URL 扫描 |
| USB 防护 | `usb_guard.py` / `usb_scanner.py` | USB 自动扫描与 Autorun 免疫 |
| 浏览器防护 | `browser_guard.py` | 浏览器配置防篡改 |
| 摄像头防护 | `camera_guard.py` | 摄像头占用监控 |
| 隐私护盾 | `privacy_shield.py` | 敏感目录保护 |
| 反 Rootkit | `anti_rootkit.py` | 用户态交叉比对（内核路径已移除） |
| 自保护 | `self_protect.py` | 安全产品自身进程/文件/注册表保护 |
| 紧急处置 | `emergency_kill.py` | F12 紧急处置 |
| 处置中心 | `response_center.py` | 检测→确认→处置→回滚→审计闭环 |
| 隔离区 | `quarantine.py` | 受感染文件隔离、还原与删除 |

### 系统与运维

| 模块 | 文件 | 功能描述 |
|------|------|----------|
| 电脑优化 | `system_optimizer.py` | 系统体检评分、启动项/服务/内存优化 |
| 垃圾清理 | `junk_cleaner.py` | 临时文件/浏览器缓存/缩略图清理 |
| 数据恢复 | `data_recovery.py` | 文件恢复与修复 |
| 漏洞修复 | `vuln_fix.py` | 系统漏洞扫描与修复入口 |
| 网络修复 | `network_repair.py` | hosts / DNS / LSP 修复 |
| 网络监控 | `network_monitor.py` | 网络连接监控 |
| 启动项扫描 | `startup_scanner.py` | 启动项识别与禁用 |
| 定时调度 | `scheduler.py` | 扫描任务调度与线程池 |
| 历史记录 | `history_manager.py` | 扫描/处置历史 |
| 策略管理 | `policy_manager.py` | 策略持久化 |
| 自定义规则 | `custom_rules.py` | 用户自定义检测规则 |
| 威胁情报 | `threat_intel.py` / `c2_intel.py` / `otx_client.py` / `avic_client.py` / `huorong_intel.py` | 多源情报聚合 |
| 游戏模式 | `game_mode.py` | 游戏时降低扫描优先级 |
| 系统托盘 | `tray_icon.py` | 托盘图标与通知 |
| 开机自启 | `auto_start.py` | `HKCU\...\Run` 注册 |
| Shell 集成 | `shell_integration.py` | 右键菜单集成 |
| 广告拦截 | `adblock.py` | 弹窗拦截 |

### 原生桥接

| 模块 | 文件 | 功能描述 |
|------|------|----------|
| 破军引擎桥接 | `native_bridge.py` | 子进程模式调用 `native_engine.exe`（JSON 通信） |
| 原生防护桥接 | `native_guard_bridge.py` | `ctypes.CDLL` 直调 `native_guard.dll`（~0.1-1ms） |
| 文件守护客户端 | `file_guard_client.py` | 连接 C++ `file_guard.exe`（**默认禁用**，见下） |

---

## 实时防护架构（三层）

实时防护是本项目最复杂的子系统，由三个可独立运行的层组成：

### 第 1 层：`realtime_guard.py`（主程序内）

```
监控线程(每目录) → 有界事件队列(10000) → 300ms 防抖 → 扫描线程池(2) → 三道闸门 → 隔离
```

- **监控**：`ReadDirectoryChangesW` 同步读取，64KB 缓冲，递归子树，每目录一条 daemon 线程
- **默认目录**：Desktop / Downloads / `%TEMP%` / `%APPDATA%` + 用户自定义
- **过滤**：仅扫描 32 种扩展名（`SCAN_EXTENSIONS`），跳过 `.tmp .log .lnk` 等；>50MB 跳过
- **背压**：队列满即丢弃并计数 `dropped_events`，绝不阻塞监控线程；防抖缓存 50000 条上限 + TTL 裁剪
- **重连**：单次会话失败后按 1s → 30s 退避自动重连；稳定运行满 5s 则重置退避
- **状态**：`watching_dirs` 只统计存活线程，线程退出后不会虚报

**三道闸门**（`threat_decision.py`，源自 2026-10-03 误隔离事故）：

| 闸门 | 判据 | 动作 |
|------|------|------|
| 0 | 规则 `confidence == low` | 仅告警，不处置 |
| 1 | 文件位于系统目录 | 走 `WinVerifyTrust` Authenticode 签名二次复核（**独立于 YARA 的第二信源**），签名有效则放行 |
| 2 | 通过前两道 | 挂起为待决项交用户决定，**15 秒无响应自动隔离** |

> 事故背景：一次扫描把 42 个 Windows 系统文件搬进隔离区，元凶规则 `EXE_in_LNK`
> 实测命中 **514/585 = 88%** 的合法 System32 文件。

**扫描优先级**：游戏模式调用 `set_priority("low")` 时，扫描线程降为
`THREAD_PRIORITY_BELOW_NORMAL` 并每文件补眠 20ms，把 CPU 让给前台游戏。

### 第 2 层：`rtguard/`（独立进程，重写版）

从零实现的后台实时防护：目录监控 + 快速扫描 + 隔离 + 托盘，**零第三方依赖**
（标准库 + 一个自编 C 匹配器）。控制 API 监听 `127.0.0.1:8022`，
由主产品 `guard.html` 的档位按钮通过 `/api/v1/rtguard/*` 代理调用。

| | 吞吐 | 22 MB 耗时 |
|---|---|---|
| **rtguard（原生 Aho-Corasick）** | **337 MB/s** | **0.065 s** |
| 旧实现（纯 Python YARA 复刻） | 0.145 MB/s | 141.8 s |

- **CPU 节流**三档：低 5% / 中 10% / 高 15%（占系统总 CPU），占空比控制而非 PID
- **监控**：真 overlapped I/O（`FILE_FLAG_OVERLAPPED` + 事件 + `WaitForSingleObject`），
  256KB 缓冲抗事件风暴，过滤位逐级降级，`stop()` 毫秒级可退出
- **默认只告警不自动隔离**（实测 `notepad.exe` 即命中 3 条 LNK 规则）

### 第 3 层：`file_guard_client.py`（C++ 守护，**默认禁用**）

`file_guard.exe` 需显式设 `YUTIAN_NATIVE_GUARD=1` 才拉起，否则直接 return。
原因：该原生层存在 `0xC0000005` 访问违规风险，会拖垮主进程。
详见 `ISSUES.md` 3.7。

---

## 前端页面（`backend/frontend/`）

单页应用式布局，暗色主题（深蓝 `#0a1f2e` + 青色 `#00bcd4`），72px 图标侧边栏。

| 页面 | 文件 | 功能 |
|------|------|------|
| 概览 | `index.html` | 系统状态总览、安全统计、威胁情报 IOC 计数、快捷入口 |
| 扫描 | `scan.html` | 快速/全盘/自定义扫描与实时进度 |
| 卫士体检 | `guard.html` | 系统健康评分、CPU 节流档位控制 |
| 垃圾清理 | `clean.html` | 垃圾扫描与清理 |
| 电脑优化 | `optimize.html` | 启动项/服务/内存优化 |
| 隔离区 | `quarantine.html` | 隔离文件管理与恢复 |
| 历史 | `history.html` | 扫描与威胁历史、病毒家族统计 |
| 日志 | `logs.html` | 系统日志查看 |
| 规则 | `rules.html` | 自定义规则管理 |
| 工具箱 | `tools.html` | 安全工具集 |
| 数据恢复 | `recovery.html` | 文件恢复与修复 |
| 沙箱 | `sandbox.html` | 沙箱分析结果 |
| 引擎 | `engine.html` | 防护模块开关（`/api/v1/protection/toggle`） |
| 设置 | `settings.html` | 主题、扫描参数、数据管理 |
| 协议 | `agreement.html` | 用户协议确认 |
| 隐私 | `privacy.html` | 隐私政策 |

公共 JS：`common.js`（API 封装）、`decision_popup.js`（威胁处置弹窗，对接三道闸门的第 2 道）。

---

## 技术栈

- **后端框架**: FastAPI + Uvicorn + WebSocket
- **前端**: 原生 HTML/CSS/JavaScript（pywebview 内嵌 WebView2）
- **打包工具**: PyInstaller（onedir 为当前发布模式）
- **数据库**: SQLite（特征库、扫描缓存、漏洞库）
- **检测引擎**: YARA + 机器学习（MalConv）+ 云查杀（AVIC/微步/OTX）+ capa 行为分析
- **原生层**: C/C++（g++ 编译为 DLL/EXE），ClamAV 作为运行库
- **容器化**: Docker + Docker Compose

---

## 依赖安装

### Python 环境

```powershell
# 要求 Python 3.14（项目使用 F:\Python314\python.exe）
# backend\libs 里 251 个 .pyd 是 cp314，换版本即废（见 ISSUES.md 3.8）
F:\Python314\python.exe -m pip install -r backend\requirements.txt
```

### `backend/requirements.txt`（全部 6 项）

| 依赖 | 版本 | 用途 |
|------|------|------|
| `fastapi` | >=0.100.0 | API 网关框架 |
| `uvicorn[standard]` | >=0.23.0 | ASGI 服务器 |
| `python-multipart` | >=0.0.6 | 文件上传支持 |
| `aiofiles` | >=23.0.0 | 异步文件 IO |
| `requests` | >=2.28.0 | HTTP 客户端（云查杀 / 情报下载） |
| `pyinstaller` | >=6.0.0 | Windows 打包为 EXE |

> ⚠️ 实际第三方 import 有 39 个，多数靠 `backend/libs` 内置副本提供
> （4,704 文件，已 gitignore）。后果见 `ISSUES.md` 3.5：内置副本拿不到上游安全补丁。

### 原生 DLL 编译

```bash
# 在 backend/engine/native_guard/ 目录下执行
g++ -O2 -shared -o native_guard.dll *.cpp \
  -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -lntdll -lwintrust \
  -static-libgcc -static-libstdc++

# rtguard 的 Aho-Corasick 匹配器（三步手工构建，原因见 rtguard/README.md）
cd rtguard\native && build.bat
```

---

## 启动命令

### 开发模式（直接运行）

```powershell
cd H:\Caelire\backend
F:\Python314\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8899
```

### 开发模式（快捷脚本）

```batch
REM 双击运行，或命令行执行
H:\Caelire\backend\启动安盾.bat
```

### Docker 部署

```bash
cd H:\Caelire\backend
docker compose up -d
docker compose logs -f
docker compose down
```

---

## 打包部署

### Windows EXE 打包

```batch
REM 方式一：使用 spec 文件打包（推荐）
cd H:\Caelire\backend
F:\Python314\python.exe -m PyInstaller 御天_onedir.spec --clean --noconfirm

REM 方式二：使用快捷脚本
H:\Caelire\backend\打包御天.cmd
```

打包产物输出到 `backend\dist\`，包含主程序 EXE、`engine/` 引擎模块、
`frontend/` 前端页面、`bingduku/` 特征库、原生引擎 `native_engine.exe` + `native_guard.dll`。

> ⚠️ 打包前注意事项见 `ISSUES.md` 3.8：`御天_onedir.spec` 硬编码 `F:\Python314\...`，
> 且打包 `H:\Caelire\bingduku`（该目录已删除，**打包前需重建**）。
> 四个 `.spec` 文件均被 `.gitignore` 排除，不在版本控制内（`ISSUES.md` 1.5）。

---

## 运行时数据目录

| 模式 | 数据位置 |
|------|----------|
| 开发模式 | `backend/engine/data/`（`db/` `logs/` `quarantine/`） |
| 打包模式 | `%LOCALAPPDATA%\Andun\data\`（只读的 `_internal/` 无法写入） |
| 根级共享 | `data/`（`scan_cache.db` / `config_save.json` / `guard_days.json`） |
| 启动诊断 | `%LOCALAPPDATA%\Andun\data\logs\startup_traceback.txt` |

日志轮转：`RotatingFileHandler` 10MB/文件保留 5 个备份，错误日志 5MB/文件保留 3 个。

---

## 关键设计约束

1. 前端 API 基址使用 `const API_BASE = ''` 动态适配
2. 病毒特征库导入使用批量事务（每批 20,000 条），SQLite MEMORY 模式 + 64MB 缓存
3. 特征库导入幂等性保证（`signature_meta` 标记）
4. 扫描线程池最大并发数 `MAX_WORKERS=8`，前台有交互时自动降为 1/4
5. 大于 200MB 文件仅校验文件头和哈希
6. 跳过系统休眠文件、页面文件、回收站文件
7. SQLite 连接全局复用，使用 `threading.Lock()` 防锁
8. 缓存策略（云查结果、文件哈希）使用 LRU 缓存，设有最大容量限制
9. 打包模式下所有可写数据落到 `%LOCALAPPDATA%\Andun`，不写只读的 `_internal/`

---

## 性能基准

| 指标 | 建议值 | 说明 |
|------|--------|------|
| 全盘扫描 >200MB 文件 | 仅校验头部 + 哈希 | `LARGE_FILE_THRESH=200MB` |
| 扫描线程池 | `MAX_WORKERS=8`（半核封顶） | 前台有交互时自动降为 1/4 |
| 事件环形队列 | 256 条 | 背压时丢弃最旧，硬上限 10000 条 |
| 实时监控事件队列 | 10000 条 | 满则丢弃并计数，不阻塞监控线程 |
| 云缓存 LRU | 最大 5,000 条 | TTL=7 天 |
| 哈希缓存 LRU | 最大 10,000 条 | TTL=2 小时 |
| WebSocket 连接数 | 50 | 实时进度推送 |
| ETW 每 Provider 速率 | 100-200 事件/秒 | Token Bucket 限流 |
| 单文件扫描超时 | 60 秒 | 防止大文件/损坏文件卡死 |
| rtguard CPU 占用 | 低 5% / 中 10% / 高 15% | 占空比控制，占系统总容量 |
| 日志轮转 | 10MB/文件，保留 5 个备份 | RotatingFileHandler |

---

## 测试

```powershell
cd H:\Caelire\backend
F:\Python314\python.exe -m pytest tests/ -v
```

现有 6 个测试文件 / 569 行，覆盖 `local_scanner` / `signature_manager` /
`scheduler` / `yara` 匹配。**测试覆盖严重不足**（4.7 万行自有代码），
建议优先补齐"检测 → 处置"主链路，见 `ISSUES.md` 3.6。

---

## 已知问题

维护在 [`ISSUES.md`](ISSUES.md)，重点：

- 🔴 反 Rootkit `_enum_processes_ntquery` 结构体布局错误 → 访问违例直接杀死解释器（`ISSUES.md` 2.1）
- 🔴 `scan_hidden_drivers()` 恒返回 0，隐藏驱动检测失效（`ISSUES.md` 2.2）
- 🟡 `app.py` 约 4,400 行、307 个路由、0 个 `APIRouter`（`ISSUES.md` 3.3）
- 🟡 自有代码 646 处 `except Exception`，安全软件里静默吞异常 = 界面显示"安全"（`ISSUES.md` 3.4）
- ⚖️ AVIC API key 已进 git 历史，推送前必须作废重签（`ISSUES.md` 3.1）
- ⚖️ ClamAV 为 GPLv2、EMBER 为 AGPL-v3，闭源分发需处理授权（`ISSUES.md` 3.10）

---

## 本机环境干扰（重要）

本机已安装**火绒安全**（`C:\Program Files\Huorong\Sysdiag\bin\hramsi.dll`，
注册为本机唯一 AMSI Provider）。实测其 `AmsiScanBuffer` 触发访问违例会**打崩 PowerShell 进程**。
它还会拦截未签名 exe 与内核驱动 —— 在本机测试御天时会与它直接冲突，
**遇到诡异崩溃时先排除环境因素**。详见 `ISSUES.md` 第四节。
