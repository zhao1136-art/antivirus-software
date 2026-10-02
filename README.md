# 御天（安盾）安全防护系统

基于 Python 的全栈安全防护软件，集成本地病毒查杀、云查杀、实时防护、防火墙、沙箱等多层安全引擎。

---

## 项目结构

```
f:\Caelire\
├── backend/                          # 后端服务（FastAPI 主程序）
│   ├── app.py                        # 主入口：FastAPI API 网关 + WebSocket
│   ├── config.py                     # 应用配置
│   ├── persistence.py                # 持久化存储（配置、守护天数）
│   ├── engine_loader.py              # 引擎模块动态加载器
│   ├── installer.py                  # 安装程序
│   ├── 御天.spec                      # PyInstaller 打包 spec
│   ├── 御天_onedir.spec               # PyInstaller onedir 打包 spec
│   ├── requirements.txt              # Python 依赖
│   ├── Dockerfile / docker-compose.yml  # Docker 容器化部署
│   │
│   ├── engine/                       # ★ 核心检测引擎（60+ 模块）
│   │   ├── local_scanner.py          # 本地病毒扫描与 APK 检测
│   │   ├── signature_manager.py      # 病毒特征库管理（SQLite）
│   │   ├── signature_downloader.py   # 特征库在线下载更新
│   │   ├── yara_scanner.py           # YARA 规则扫描引擎
│   │   ├── ml_scanner.py             # 机器学习检测引擎
│   │   ├── cloud_scanner.py          # 云查杀引擎
│   │   ├── avic_client.py            # AVIC 云查杀客户端
│   │   ├── deep_analyzer.py          # 深度分析引擎
│   │   ├── dex_parser.py             # DEX 字节码解析器（Android APK）
│   │   ├── realtime_guard.py         # 实时防护引擎
│   │   ├── file_guard.py             # 文件防护
│   │   ├── process_guard.py          # 进程防护
│   │   ├── registry_guard.py         # 注册表防护
│   │   ├── browser_guard.py          # 浏览器防护
│   │   ├── camera_guard.py           # 摄像头防护
│   │   ├── download_guard.py         # 下载防护
│   │   ├── ransomware_shield.py      # 勒索软件护盾
│   │   ├── privacy_shield.py         # 隐私护盾
│   │   ├── behavior_block.py         # 行为阻断
│   │   ├── anti_rootkit.py           # 反 Rootkit（内核 + 用户态交叉比对）
│   │   ├── self_protect.py           # 安全产品自保护（进程/文件/注册表/服务）
│   │   ├── response_center.py        # 处置中心（检测→确认→处置→回滚→审计）
│   │   ├── quarantine.py             # 隔离区管理
│   │   ├── firewall.py               # 防火墙引擎
│   │   ├── hips.py                   # 主机入侵防御系统
│   │   ├── sandbox.py                # 沙箱分析
│   │   ├── honeypot_manager.py       # 蜜罐管理
│   │   ├── network_monitor.py        # 网络监控
│   │   ├── threat_intel.py           # 威胁情报
│   │   ├── c2_intel.py               # C2 情报分析
│   │   ├── otx_client.py             # OTX 情报客户端
│   │   ├── emergency_kill.py         # 紧急查杀
│   │   ├── data_recovery.py          # 数据恢复
│   │   ├── network_repair.py         # 网络修复
│   │   ├── system_guard.py           # 系统防护
│   │   ├── integrity.py              # 完整性校验
│   │   ├── usb_scanner.py            # USB 设备扫描
│   │   ├── startup_scanner.py        # 启动项扫描
│   │   ├── watchdog.py               # 文件监控
│   │   ├── kernel_bridge.py          # 内核桥接
│   │   ├── native_bridge.py          # 原生桥接
│   │   ├── native_guard_bridge.py    # 原生防护桥接
│   │   ├── auto_start.py             # 开机自启
│   │   ├── game_mode.py              # 游戏模式
│   │   ├── adblock.py                # 广告拦截
│   │   ├── notification.py           # 通知管理
│   │   ├── tray_icon.py              # 系统托盘图标
│   │   ├── optimizer.py              # 性能优化器
│   │   ├── system_optimizer.py       # 电脑优化引擎（体检/启动项/服务/内存）
│   │   ├── junk_cleaner.py           # 垃圾清理引擎（临时文件/浏览器缓存等）
│   │   ├── scheduler.py              # 定时任务调度
│   │   ├── history_manager.py        # 历史记录管理
│   │   ├── report_logger.py          # 报告日志
│   │   ├── custom_rules.py           # 自定义规则
│   │   ├── policy_manager.py         # 策略管理
│   │   ├── shell_integration.py      # Shell 集成
│   │   ├── andun_client.py           # 安盾客户端
│   │   ├── file_guard_client.py      # 文件防护客户端
│   │   ├── engine.py                 # 引擎核心
│   │   ├── main.py                   # 主模块
│   │   ├── loader.py                 # 加载器
│   │   ├── helpers.py                # 辅助函数
│   │   ├── exceptions.py             # 异常定义
│   │   ├── perf.py                   # 性能监控
│   │   ├── version.py                # 版本信息
│   │   └── yarGen.py                 # YARA 规则生成
│   │
│   ├── frontend/                     # 前端页面（静态 HTML）
│   │   ├── index.html                # 主页面
│   │   ├── scan.html                 # 扫描页面
│   │   ├── firewall.html             # 防火墙页面
│   │   ├── quarantine.html           # 隔离区页面
│   │   ├── history.html              # 历史记录页面
│   │   ├── logs.html                 # 日志页面
│   │   ├── rules.html                # 规则管理页面
│   │   ├── tools.html                # 工具箱页面
│   │   ├── recovery.html             # 数据恢复页面
│   │   ├── sandbox.html              # 沙箱页面
│   │   ├── guard.html                # 卫士体检页面
│   │   ├── optimize.html             # 电脑优化页面
│   │   ├── clean.html                # 垃圾清理页面
│   │   ├── settings.html             # 设置页面
│   │   ├── agreement.html            # 用户协议
│   │   └── privacy.html              # 隐私政策
│   │
│   ├── driver/                       # 驱动文件
│   ├── data/                         # 数据目录
│   ├── database/                     # 数据库目录
│   ├── p2p_tunnel/                   # P2P 隧道模块
│   ├── libs/                         # 第三方库
│   └── vigil/                        # Vigil 安全模块
│
├── installer/                        # 安装/卸载程序
│   ├── installer.py                  # 安装程序
│   ├── installer_common.py           # 安装公共模块
│   ├── uninstaller.py                # 卸载程序
│   ├── build_installer.py            # 构建脚本
│   ├── 构建安装程序.cmd                # 构建命令
│   └── 御天.zip                       # 安装包压缩文件
│
├── bingduku/                         # 病毒特征库文件
│
├── release/                          # 发布版本目录
├── data/                             # 运行数据
│   └── guard_days.json               # 守护天数记录
│
├── Yara-rules-master/                # YARA 规则集
├── capa-master/                      # CAPA 分析工具
├── ember-master/                     # EMBER 数据集/模型
├── maltrail-master/                  # Maltrail 恶意流量检测
├── pe-sieve-master/                  # PE-sieve 进程扫描
├── libpeconv-master/                 # libpeconv PE 处理库
├── vigil-main/                       # Vigil 安全引擎
├── yarGen-master/                    # YARA 规则生成器
├── C2IntelFeeds-master/              # C2 情报源
├── clamav-main/                      # ClamAV 源码
├── clamav-1.5.3.win.x64/             # ClamAV Windows x64
├── clamav-1.5.3.win.arm64/           # ClamAV Windows ARM64
│
├── deploy-staging/                   # 部署测试环境
├── deploy-config/                    # 部署配置
├── test_samples/                     # 测试样本
│
├── 启动安盾.bat                        # 启动脚本
├── 打包御天.cmd                        # 打包命令
├── logo_icon_b64.txt                  # Logo 图标 Base64
└── 安盾_data.zip                       # 数据压缩包
```

---

## 核心引擎模块（engine/）

| 模块 | 文件 | 功能描述 |
|------|------|----------|
| 本地扫描 | `local_scanner.py` | 本地病毒查杀，支持 Windows PE 和 Android APK 检测 |
| 特征库 | `signature_manager.py` | 病毒特征库管理，SQLite 存储，批量导入 |
| YARA 扫描 | `yara_scanner.py` | 基于 YARA 规则的恶意代码匹配 |
| 机器学习 | `ml_scanner.py` | 基于 ML 模型的可疑文件分类 |
| 云查杀 | `cloud_scanner.py` | 云端查杀引擎集成 |
| DEX 解析 | `dex_parser.py` | Android DEX 字节码解析 |
| 实时防护 | `realtime_guard.py` | 实时文件/进程监控与拦截 |
| 防火墙 | `firewall.py` | 网络流量过滤与防火墙规则 |
| HIPS | `hips.py` | 主机入侵防御系统 |
| 沙箱 | `sandbox.py` | 可疑文件沙箱隔离分析 |
| 勒索防护 | `ransomware_shield.py` | 勒索软件行为检测与阻断 |
| 反 Rootkit | `anti_rootkit.py` | 内核级 Rootkit 检测 |
| 威胁情报 | `threat_intel.py` | 威胁情报聚合与分析 |
| 隔离区 | `quarantine.py` | 受感染文件隔离与恢复 |
| 电脑优化 | `system_optimizer.py` | 系统体检评分、启动项/服务/内存优化 |
| 垃圾清理 | `junk_cleaner.py` | 临时文件/浏览器缓存/缩略图等垃圾清理 |

---

## 前端页面（frontend/）

| 页面 | 文件 | 功能 |
|------|------|------|
| 主页 | `index.html` | 系统状态总览与快速操作 |
| 扫描 | `scan.html` | 全盘/快速/自定义扫描 |
| 防火墙 | `firewall.html` | 防火墙规则配置 |
| 隔离区 | `quarantine.html` | 隔离文件管理与恢复 |
| 历史 | `history.html` | 扫描与防护历史记录 |
| 日志 | `logs.html` | 系统日志查看 |
| 规则 | `rules.html` | 自定义规则管理 |
| 工具箱 | `tools.html` | 安全工具集 |
| 数据恢复 | `recovery.html` | 文件恢复与修复 |
| 沙箱 | `sandbox.html` | 沙箱分析结果 |
| 卫士体检 | `guard.html` | 系统状态体检与一键优化入口 |
| 电脑优化 | `optimize.html` | 启动项/服务/内存优化 |
| 垃圾清理 | `clean.html` | 垃圾扫描与清理 |
| 设置 | `settings.html` | 系统设置（含协议页） |
| 协议 | `agreement.html` | 用户协议页面 |
| 隐私 | `privacy.html` | 隐私政策页面 |

---

## 技术栈

- **后端框架**: FastAPI + Uvicorn + WebSocket
- **前端**: 原生 HTML/CSS/JavaScript（嵌入式 WebView）
- **打包工具**: PyInstaller
- **数据库**: SQLite
- **检测引擎**: YARA + ML + 云查杀
- **内核驱动**: C 语言 + Windows Driver Kit
- **原生引擎**: C++ (g++ 编译为 DLL/EXE)
- **容器化**: Docker + Docker Compose

---

## 依赖安装

### Python 环境

```powershell
# 要求 Python 3.14（项目使用 F:\Python314\python.exe）
# 安装依赖
F:\Python314\python.exe -m pip install -r requirements.txt
```

### requirements.txt

| 依赖 | 版本 | 用途 |
|------|------|------|
| `fastapi` | >=0.100.0 | API 网关框架 |
| `uvicorn[standard]` | >=0.23.0 | ASGI 服务器 |
| `python-multipart` | >=0.0.6 | 文件上传支持 |
| `aiofiles` | >=23.0.0 | 异步文件 IO |
| `requests` | >=2.28.0 | HTTP 客户端（云查杀 / 情报下载） |
| `pyinstaller` | >=6.0.0 | Windows 打包为 EXE |
| `numpy` | — | 机器学习特征计算 |
| `pefile` | — | PE 文件解析 |
| `lightgbm` | — | 机器学习模型推理 |
| `lief` | — | 二进制文件解析 |
| `oletools` | — | Office 文档分析 |
| `psutil` | — | 系统进程/网络信息 |
| `tqdm` | — | 进度条 |
| `webview` | — | 嵌入式 WebView 前端 |
| `cffi` | — | C 扩展调用 |
| `pycparser` | — | C 代码解析 |

### 驱动编译

```batch
REM 前置条件：WDK + Visual Studio（含 C++ 桌面开发 + 驱动开发）
REM 在"开发人员命令提示符"中运行：
cd backend\driver\andun_driver
build.bat           REM 编译 Release 版本（产物 andun.sys）
build.bat debug     REM 编译 Debug 版本
```

### 原生 DLL 编译

```bash
# 在 backend\engine\native_guard\ 目录下执行
g++ -O2 -shared -o native_guard.dll *.cpp \
  -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -lntdll -lwintrust \
  -static-libgcc -static-libstdc++
```

---

## 启动命令

### 开发模式（直接运行）

```powershell
# 进入后端目录
cd f:\Caelire\backend

# 启动 FastAPI 服务（端口 8899）
F:\Python314\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8899 --reload
```

### 开发模式（快捷脚本）

```batch
REM 双击运行，或命令行执行
f:\Caelire\backend\启动安盾.bat
```

### Docker 部署

```bash
# 构建镜像并启动
cd f:\Caelire\backend
docker compose up -d

# 查看日志
docker compose logs -f

# 停止
docker compose down
```

---

## 打包部署

### Windows EXE 打包

```batch
REM 方式一：使用 spec 文件打包（推荐）
cd f:\Caelire\backend
F:\Python314\python.exe -m PyInstaller 御天.spec --clean --noconfirm

REM 方式二：使用快捷脚本
f:\Caelire\backend\pack_andun.bat
```

打包产物输出到 `backend\dist\`，包含：
- 主程序 EXE
- `engine/` 引擎模块
- `frontend/` 前端页面
- `driver/` 驱动文件（含 `andun.sys`）
- `bingduku/` 病毒特征库
- 原生引擎 `native_engine.exe` + `native_guard.dll`

### 驱动安装/卸载

```batch
REM 安装驱动（需要管理员权限）
sc create AndunDriver type= kernel start= demand binPath= "F:\Caelire\backend\dist\driver\andun_driver\andun.sys"
sc start AndunDriver

REM 卸载驱动
sc stop AndunDriver
sc delete AndunDriver
```

---

## 内核驱动（`backend/driver/andun_driver/`）

基于 Windows Driver Kit (WDK) 用 C 语言编写的内核级安全驱动，编译产物为 `andun.sys`。通过 Minifilter、WFP、进程/注册表/对象回调实现系统级监控与拦截。

### 源文件架构（12 个 .c 文件 + 1 个 .h 头文件）

| 文件 | 代码量 | 功能 | 核心技术 |
|------|--------|------|----------|
| `andun.h` | 331 行 | 公共头文件：IOCTL 码、结构体、函数声明 | `#pragma pack(push, 1)` 1 字节对齐 |
| `driver_main.c` | 190 行 | 驱动入口 `DriverEntry`，按序加载/反序卸载 8 个子系统 | DriverObject + IRP 分发 |
| `file_filter.c` | 429 行 | Minifilter 文件系统过滤（创建/写入/删除/重命名） | FltRegisterFilter + PreOperation 回调 |
| `process_callback.c` | 389 行 | 进程创建/终止监控，阻断恶意进程启动 | PsSetCreateProcessNotifyRoutineEx |
| `registry_callback.c` | 347 行 | 注册表写入/删除监控 | CmRegisterCallbackEx |
| `object_callback.c` | 426 行 | 对象句柄操作监控 + PID 保护列表 | ObRegisterCallbacks |
| `network_filter.c` | 536 行 | WFP 网络过滤（IPv4 出站/入站 ALE 层） | FwpsCalloutRegister + ALE_AUTH_CONNECT_V4 |
| `event_queue.c` | 228 行 | 环形事件队列（256 条），自旋锁保护 | 无锁队列 + DISPATCH_LEVEL 安全 |
| `rule_engine.c` | 460 行 | 规则引擎：通配符匹配、5 种规则类型 | 1024 条规则上限 |
| `rootkit_scan.c` | 新增 | Rootkit 内核扫描（EPROCESS 遍历 / SSDT / Inline Hook / 回调劫持） | 只读检测 + MmIsAddressValid + __try 双重保护 |
| `self_protect.c` | 新增 | 自保护规则预置（文件/注册表/服务） | 向规则引擎注入自保护规则 + 独立 IOCTL |
| `response.c` | 新增 | 处置响应原语（终止进程/隔离文件/下发拦截规则） | ZwOpenProcess + ZwTerminateProcess + 文件重命名隔离 |

### 驱动加载流程

```
DriverEntry
  ├─ 1. 初始化全局统计 + 自旋锁
  ├─ 2. EventQueueInit()              事件队列
  ├─ 3. RuleEngineInit()              规则引擎
  ├─ 4. ProtectedPidInit()            受保护 PID 列表（64 个）
  ├─ 5. SelfProtectInit()             自保护初始化（预置安装目录/注册表保护规则）
  ├─ 6. DeviceControlInit()           设备对象 \Device\AndunDriver + 符号链接
  ├─ 7. FileFilterInit()              Minifilter 注册并启动过滤
  ├─ 8. ProcessCallbackInit()         进程创建/终止回调
  ├─ 9. RegistryCallbackInit()        注册表操作回调
  ├─ 10. ObjectCallbackInit()         对象句柄回调
  └─ 11. NetworkFilterInit()          WFP 网络过滤（出站 + 入站）
```

卸载时按严格反序销毁：NetworkFilter → ObjectCallback → RegistryCallback → ProcessCallback → FileFilter → DeviceControl → SelfProtect → ProtectedPid → RuleEngine → EventQueue。

### 17 个 IOCTL 控制码

| IOCTL | 功能 | 方向 |
|-------|------|------|
| **基础通信** | | |
| `IOCTL_ANDUN_GET_EVENTS` (0x800) | 批量读取事件（最多 32 条/次） | 内核 → 用户态 |
| `IOCTL_ANDUN_ADD_RULE` (0x801) | 下发拦截规则 | 用户态 → 内核 |
| `IOCTL_ANDUN_DEL_RULE` (0x802) | 按 ruleId 删除规则 | 用户态 → 内核 |
| `IOCTL_ANDUN_CLEAR_RULES` (0x803) | 清空所有规则 | 用户态 → 内核 |
| `IOCTL_ANDUN_SET_CONFIG` (0x804) | 设置 6 个开关 | 用户态 → 内核 |
| `IOCTL_ANDUN_GET_CONFIG` (0x805) | 读取当前配置 | 内核 → 用户态 |
| `IOCTL_ANDUN_PROTECT_PID` (0x806) | 将 PID 加入保护列表 | 用户态 → 内核 |
| `IOCTL_ANDUN_UNPROTECT_PID` (0x807) | 从保护列表移除 PID | 用户态 → 内核 |
| `IOCTL_ANDUN_ROOTKIT_SCAN` (0x808) | 触发 Rootkit 扫描（4 维聚合） | 用户态 → 内核 |
| `IOCTL_ANDUN_GET_STATS` (0x809) | 读取统计信息（10 个计数器） | 内核 → 用户态 |
| **自保护（0x80A-0x80D）** | | |
| `IOCTL_ANDUN_SELFPROTECT_PROCESS` (0x80A) | 下发 agent PID 保护（ObRegisterCallbacks 剥离危险权限） | 用户态 → 内核 |
| `IOCTL_ANDUN_SELFPROTECT_FILE` (0x80B) | 下发安装目录保护（Minifilter 拦截写/删除） | 用户态 → 内核 |
| `IOCTL_ANDUN_SELFPROTECT_REGISTRY` (0x80C) | 下发注册表键保护（CmCallback 拦截篡改） | 用户态 → 内核 |
| `IOCTL_ANDUN_SELFPROTECT_SERVICE` (0x80D) | 下发服务名保护（拦截 DeleteService/ChangeServiceConfig） | 用户态 → 内核 |
| **处置响应（0x80E-0x810）** | | |
| `IOCTL_ANDUN_RESPONSE_KILL_PROCESS` (0x80E) | 终止恶意进程（受保护 PID 不可被终止） | 用户态 → 内核 |
| `IOCTL_ANDUN_RESPONSE_QUARANTINE_FILE` (0x80F) | 隔离恶意文件（重命名为 .andunq） | 用户态 → 内核 |
| `IOCTL_ANDUN_RESPONSE_BLOCK_RULE` (0x810) | 下发即时拦截规则 | 用户态 → 内核 |

### 11 种事件类型

| 事件 | 枚举值 | 触发场景 |
|------|--------|----------|
| `EventFileCreate` | 1 | 文件创建（含写入/删除意图） |
| `EventFileWrite` | 2 | 文件写入 |
| `EventFileDelete` | 3 | 文件删除/重命名 |
| `EventProcessCreate` | 4 | 进程创建（可阻断） |
| `EventProcessTerminate` | 5 | 进程退出（自动清理保护 PID） |
| `EventRegistrySet` | 6 | 注册表写入 |
| `EventRegistryDelete` | 7 | 注册表删除 |
| `EventNetworkConnect` | 8 | 网络连接（出站/入站） |
| `EventHandleOpen` | 9 | 句柄打开 |
| `EventDriverLoad` | 10 | 驱动加载 |
| `EventRootkitDetected` | 11 | Rootkit 检测命中 |

### 编译要求

```batch
REM 前置条件：WDK + Visual Studio（含 C++ 桌面开发 + 驱动开发）
REM 在"开发人员命令提示符"中运行：
build.bat           REM 编译 Release 版本
build.bat debug     REM 编译 Debug 版本
```

链接库：`ntoskrnl.lib hal.lib fltMgr.lib fwpkclnt.lib ndis.lib uuid.lib`

---

## Python ↔ 驱动通信桥接

### kernel_bridge.py（695 行）

通过 `ctypes` 调用 Windows API 与 `andun.sys` 通信，是用户态与内核态的唯一桥梁：

```
Python 用户态 (kernel_bridge.py)
  │  ctypes.windll.kernel32.CreateFileW("\\\\.\\AndunDriver")
  │  ctypes.windll.kernel32.DeviceIoControl(IOCTL_xxx)
  ▼
andun.sys 内核态 (driver_main.c → DeviceControlIoctlDispatch)
```

**关键设计**：
- 所有结构体（`ANDUN_EVENT`, `ANDUN_RULE`, `ANDUN_CONFIG`, `ANDUN_STATS`）使用 `_pack_=1`，与 C 端 `#pragma pack(push, 1)` 严格对齐
- FILETIME → Unix 时间戳转换（`_filetime_to_unix`）
- 事件轮询守护线程每秒读取驱动事件队列，分发给注册的处理器
- 驱动未安装时 `connect()` 返回 `False`，自动降级，不影响其他模块
- 单例模式（`get_kernel_bridge()`），全局唯一连接

---

## C++ 原生引擎

### 破军引擎 — native_engine.exe（子进程模式）

**桥接层**：`native_bridge.py`（170 行），通过 `subprocess.run` 调用 `native_engine.exe`，JSON 通信。

| 能力 | 命令 | 说明 |
|------|------|------|
| 版本/自检 | `version`, `selftest` | 引擎可用性验证 |
| SHA256 | `sha256 <file>` | 文件哈希计算 |
| PE 解析 | `peparse <file>` | 节区/RWX/熵值/导入表/签名 |
| 启发式检测 | `heuristic <7参数>` | 7 维特征打分（RWX/熵/API/子系统/签名/URL/代码段） |
| 系统巡检 | `processes`, `startup`, `network`, `sysinfo` | 进程/启动项/网络/系统信息 |
| 隔离区 | `qmove`, `qlist` | 文件移动/恢复/列表 |

### 原生防护引擎 — native_guard.dll（ctypes 直调模式）

**桥接层**：`native_guard_bridge.py`（392 行），通过 `ctypes.CDLL` 直接加载 DLL，延迟从子进程模式的 ~15-50ms 降至 ~0.1-1ms。

**DLL 编译**（`native_guard_bridge.py` 注释）：
```bash
g++ -O2 -shared -o native_guard.dll *.cpp \
  -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -lntdll -lwintrust \
  -static-libgcc -static-libstdc++
```

**C 内存管理**：所有函数返回 `char*`（JSON），Python 侧解析后调用 `guard_free_string` 释放 C 侧堆内存。

| 对抗模块 | 接口 | 检测能力 |
|----------|------|----------|
| **进程注入对抗** | `scan_all_memory`, `enum_all_modules`, `scan_threads`, `dump_memory` | 匿名可执行内存 / 远程线程 / 未签名模块 / 内存转储 |
| **无文件攻击对抗** | `scan_cmdlines`, `check_wmi_consumers` | LOLBins 可疑命令行（powershell/wmic/mshta 等）/ WMI 持久化后门 |
| **持久化木马对抗** | `scan_persistence` | Run/RunOnce/Services/ActiveSetup/IFEO/屏保/启动文件夹/AppInit_DLLs/Winlogon/BootExecute/打印监视器/BHO/LSA 等 20+ 通道 |
| **网络侧补强** | `enum_tcp_connections`, `enum_tcp_with_risk` | TCP 连接枚举（IPv4+IPv6）/ 恶意端口标记 / C2 情报联动 |
| **ETW 事中检测** | `etw_start/stop/status/get_events`, `etw_get_correlations`, `etw_process_tree`, `etw_health` | 9 个 Provider 覆盖（Threat-Intelligence / Kernel-Process / Kernel-File / Kernel-Registry / DNS-Client / PowerShell / WMI-Activity / DotNETRuntime / Sysmon）；事件关联引擎（攻击链检测）；进程树行为评分；Provider 健康自保护 |
| **AMSI 防篡改** | `scan_amsi_tamper` | 检测各进程 `amsi.dll!AmsiScanBuffer` 的 Inline Hook |
| **ETW 防篡改** | `scan_etw_tamper` | 检测 `ntdll!EtwEventWrite` 是否被 Patch + 会话存活 |

**便捷工具函数**（供其他模块直接调用）：
- `quick_inject_scan()` — 一键扫描所有进程注入迹象（内存 + 模块 + 线程）
- `quick_fileless_scan()` — 快速无文件攻击检测（命令行 + WMI）
- `quick_network_scan(c2_intel)` — 网络扫描 + C2 情报匹配

---

## 反 Rootkit 引擎（`anti_rootkit.py` + `rootkit_scan.c`）

通过内核驱动 `IOCTL_ANDUN_ROOTKIT_SCAN` 执行 4 维聚合扫描，一次性返回内核进程链表、驱动列表、钩子信息和回调数组，用户态做交叉比对。驱动不可用时降级为用户态检测。

### 4 维检测能力

| 维度 | 驱动侧实现 | 用户态比对逻辑 |
|------|-----------|---------------|
| **隐藏进程** | 遍历 `EPROCESS.ActiveProcessLinks` 双链表（最多 256 个） | 内核 PID 集合 - 用户态 Toolhelp32 PID 集合 = 隐藏进程 |
| **隐藏驱动** | 遍历 `PsLoadedModuleList`，标记 `section_unloaded=1` 的无文件驱动 | 内核驱动名 vs `EnumDeviceDrivers` + 58 个可信驱动白名单 |
| **内核钩子** | 比对 `KiServiceTable` 20 个关键函数地址 + 序言前 5 字节 Inline Hook 检测 | 解析 `hook_type`（0=SSDT, 1=IRP, 2=Inline）+ 原始/当前字节对比 |
| **回调劫持** | 定位 `PsSetCreateProcessNotifyRoutine`/`CmRegisterCallback`/`ObRegisterCallbacks` 回调数组 | 检查回调地址是否落在已加载驱动模块地址范围内 |

**安全设计**：驱动侧只读检测，绝不写入内核表（SSDT 受 PatchGuard 保护）；所有指针访问包裹 `MmIsAddressValid` + `__try/__except` 双重保护，防止 BSOD。

---

## 安全产品自保护（`self_protect.py` + `self_protect.c`）

防止杀软自身成为攻击目标，通过 4 个 IOCTL（0x80A-0x80D）下发保护配置到驱动，驱动不可用时用户态 ACL 兜底。

| 防护维度 | 内核层 | 用户态兜底 |
|----------|--------|-----------|
| **进程防护** | 自动将 agent PID 加入 `ObRegisterCallbacks` 保护列表，剥离 `PROCESS_TERMINATE`/`PROCESS_VM_WRITE` 等危险权限 | — |
| **文件防护** | 向规则引擎预置安装目录保护规则（`.exe/.dll/.dat` 禁止外部写/删除），规则 ID 从 `0xFFF00000` 起 | ACL 加固安装目录 |
| **注册表防护** | 保护 `HKLM\...\Run\Andun*` 和 `HKLM\...\Services\Andun*` 键不被篡改 | ACL 加固注册表键 |
| **服务防护** | 拦截 `DeleteService`/`ChangeServiceConfig` 针对 `AndunAgent` 服务 | 服务 ACL 加固 |

---

## 处置中心（`response_center.py` + `response.c`）

统一编排检测 → 确认 → 处置 → 回滚 → 审计闭环。通过 3 个 IOCTL（0x80E-0x810）执行驱动侧原语。

| 环节 | 能力 | 说明 |
|------|------|------|
| **检测** | 消费 ETW 攻击链 / 反 Rootkit / 病毒扫描结果 | 多种检测源汇聚 |
| **确认** | 置信度阈值判定（默认 `severity>=3` 自动处置） | 受保护进程（agent 自身）绝不处置 |
| **处置** | 终止进程 + 隔离文件（`.andunq`）+ 下发拦截规则 | 驱动侧原语：`ZwOpenProcess` + `ZwTerminateProcess` + 文件重命名 |
| **回滚** | 临时规则超时自动移除（默认 300 秒） | 处置记录保留供审计 |
| **审计** | JSON 行追加到 `%ProgramData%\Andun\response_audit.jsonl` | 防篡改日志链 |

---

## 威胁情报下载（`signature_downloader.py`）

多源威胁情报自动下载与导入，配合 `signature_manager.py` 的幂等导入机制。

| 数据源 | 类型 | 说明 |
|--------|------|------|
| **ESET malware-ioc** | SHA256 哈希 | 148+ 恶意软件家族 IOC 仓库 |
| **Blocklist.de** | IP 地址 | 全球 fail2ban 服务器报告恶意 IP（25,000+ 条） |

导入流程：下载 → 解析 → 批量事务写入（20,000 条/批）→ 更新 `signature_meta` 版本标记。

---

## 关键设计约束

1. 前端 API 基址使用 `const API_BASE = ''` 动态适配
2. 病毒特征库导入使用批量事务（每批 20,000 条），SQLite MEMORY 模式 + 64MB 缓存
3. 特征库导入幂等性保证（`signature_meta` 标记）
4. 扫描线程池最大并发数 `MAX_WORKERS=8`
5. 大于 200MB 文件仅校验文件头和哈希
6. 跳过系统休眠文件、页面文件、回收站文件
7. SQLite 连接全局复用，使用 `threading.Lock()` 防锁
8. 缓存策略（云查结果、文件哈希）使用 LRU 缓存，设有最大容量限制

---

## 性能基准

| 指标 | 建议值 | 说明 |
|------|--------|------|
| 全盘扫描 >200MB 文件 | 仅校验头部 + 哈希，不全文读取 | `LARGE_FILE_THRESH=200MB`，`LARGE_FILE_HEADER_READ=4MB` |
| 扫描线程池 | `MAX_WORKERS=8`（半核封顶） | 前台有交互时自动降为 1/4 |
| 事件环形队列 | 256 条 | 背压时丢弃最旧，硬上限 10000 条 |
| 云缓存 LRU | 最大 5,000 条 | TTL=7 天 |
| 哈希缓存 LRU | 最大 10,000 条 | TTL=2 小时 |
| WebSocket 连接数 | 50 | 实时进度推送 |
| ETW 每 Provider 速率 | 100-200 事件/秒 | Token Bucket 限流 |
| 单文件扫描超时 | 60 秒 | 防止大文件/损坏文件卡死 |
| 云查询最小间隔 | 0.05 秒 | 约 20 次/秒，防止刷爆云端 API |
| 日志轮转 | 10MB/文件，保留 5 个备份 | RotatingFileHandler |

---

## 驱动数字签名

Win10/11 x64 强制内核驱动签名。

### 开发环境
```bash
# 启用测试模式（需重启）
bcdedit /set testsigning on
# 加载后验证
sc query AndunDriver
```

### 生产部署
驱动 `andun.sys` 正式部署前必须通过以下之一签名：
- **WHQL 签名**（推荐）：通过 Windows Hardware Lab Kit (HLK) 认证，提交到 Microsoft Partner Center
- **EV 证书签名**：使用扩展验证 (EV) 代码签名证书，提交到 Microsoft 签名门户获取 Microsoft 签名

> 注意：普通代码签名证书（非 EV）在 Secure Boot 开启的 Win10/11 系统上无法加载内核驱动。

### 卸载清理
```bash
# 以管理员身份运行
installer\cleanup.bat
# 清理内容：注册表服务项、Minifilter 实例、%ProgramData%\Andun\ 映射文件、WFP 过滤残留
```

---

## 生产环境部署

- FastAPI `/docs`、`/redoc` 已关闭（生产模式）
- 全局异常处理器兜底，避免 500 裸奔
- 日志使用 `RotatingFileHandler` 按大小轮转（10MB/文件，5 个备份 + 错误日志 5MB/文件，3 个备份）
- 健康检查端点 `GET /api/health`：驱动状态、签名库版本、引擎版本、运行时长、内存占用、磁盘空间
- 配置热加载端点 `POST /api/config/reload`：无需重启即可刷新扫描开关、网络监控间隔、云查杀引擎优先级