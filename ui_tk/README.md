# 御天 Tkinter 桌面界面（新 UI）

原界面的替代实现：**不用 HTML**，纯 Python 标准库 `tkinter`。

> **当前状态：已是主程序的正式界面。**
> `python backend/app.py` 直接启动本 Tk 界面；`backend/app.py` 里的内嵌
> WebView2 链路（pywebview / pythonnet / splash）已**整体删除**。
>
> 两种启动方式：
> - `python backend/app.py` —— 主程序：同进程起 uvicorn + 后台防护，再开 Tk 界面
> - `python ui_tk/run_ui.py` —— 单独跑界面：界面自己拉起并管理后端进程
>
> 两种方式下界面都不做任何后台防护工作，防护逻辑全在后端进程内。
> 界面只是 HTTP 客户端，后端没在跑也能启动（显示"后端未连接"）。

---

## 为什么不用 HTML

原界面是 `backend/frontend/*.html` + pywebview（内嵌 WebView2）。这条链路的
代价在项目里已经记了不少：

| 问题 | 证据 |
|------|------|
| WebView2 运行时依赖 | Windows 10 需预装 Edge WebView2；未装则回退系统浏览器 |
| pythonnet / .NET 加载受路径影响 | `Python.Runtime.dll` 与 `WebView2.Core.dll` 位于 `H:\Caelire\` 下时 `Assembly.LoadFrom` / `FileLoadException` 失败，必须复制到 `%LOCALAPPDATA%` 暂存 |
| 需要把「后端进程 + 内嵌浏览器 + 前端资源」三层拼起来才能看到一个窗口 | 原 `frontend_launcher.py` + `logo_splash.py` + `app.py` 的启动引导 |
| 前端是 16 个独立 HTML，状态靠轮询/WebSocket 手工同步 | —— |

Tkinter 方案把其中两层（浏览器内核 + HTML 资源）直接去掉：**一个 Python 进程，
一个事件循环，控件就是对象**。

**截至本次改动，上面三行"证据"对应的代码已经从主程序里删掉了**：
`app.py` 不再 import webview / pythonnet，不再有 runtime 暂存，不再有 splash；
`frontend_launcher.py` 也改为用系统浏览器打开。只有 `logo_splash.py` 这个文件
还留在磁盘上（已无人引用，属死代码）。

---

## 技术选型

**Tkinter**（Python 标准库），零第三方依赖。

选它而不是 PySide6 / PyQt / Flet / Dear PyGui 的理由：

1. **零依赖**——与项目既有取向一致（`rtguard` 的卖点就是"零第三方依赖"）；
   `backend/libs` 那套内置副本的教训见 `ISSUES.md` 3.5（拿不到上游安全补丁）。
2. **PyInstaller 打包无额外负担**——Tkinter 是标准库，不需要为 GUI 框架再拉
   上百 MB 的运行库。
3. **项目已有设计储备**——`ai_learning_results/Tkinter_GUI/` 与
   `ai_learning_results/Tkinter事件循环与动画驱动/` 记录了暗色仪表盘、
   Canvas 滚动容器、`after()` 动画、开关交互的具体做法，本实现直接沿用。

代价（见文末「已知限制」）：观感不如 Qt 现代，控件无圆角/阴影/透明度。

---

## 目录结构

```
ui_tk/
├── README.md                  # 本文件
├── run_ui.py                  # 入口（含 --self-test 无窗口自检）
├── 自检.bat                    # 双击跑自检（绕过坏掉的 PowerShell）
├── 启动界面.bat                # 双击启动界面
└── andun_ui/
    ├── __init__.py
    ├── theme.py               # 配色 / 字体解析（对齐既有 HTML 主题与设计笔记）
    ├── api.py                 # HTTP 客户端 + 线程→主线程桥 + 格式化工具
    ├── backend.py             # 后端进程管理（探测/拉起/就绪等待/停止）+ 界面偏好
    ├── widgets.py             # Card / ScrollableFrame / ToggleSwitch / PulseDot / …
    ├── app.py                 # 主窗口：侧边栏导航 + 页面容器 + 后端连通性轮询
    └── pages/
        ├── overview.py        # 概览：状态、统计、防护开关、待决威胁、最近活动
        ├── scan.py            # 病毒扫描：快速/全盘/自定义 + 进度 + 结果
        ├── quarantine.py      # 隔离区：还原 / 永久删除（含二次确认）
        ├── clean.py           # 垃圾清理：扫描 / 分类勾选 / 执行 / 历史
        ├── optimize.py        # 电脑优化：体检 / 一键优化 / 启动项 / 服务
        ├── tools.py           # 安全工具：14 个工具区块
        ├── recovery.py        # 数据恢复：快照监控 / 文件版本 / 还原 / 设置
        ├── rules.py           # 规则管理：列表 / 新增 / 模板 / 导入导出
        ├── history.py         # 历史记录：统计 / 家族分布 / 检索 / 清空
        ├── engine.py          # 引擎启动：引擎清单 / ETW / AMSI / 辅助功能
        ├── logs.py            # 日志报告：威胁/扫描日志 + 过滤 + 清空
        └── settings.py        # 设置：后端地址、引擎/特征库信息、系统健康
```

---

## 运行

```powershell
# 正常启动（需先自行启动 backend/app.py，否则显示「后端未连接」）
F:\Python314\python.exe ui_tk\run_ui.py

# 指定后端地址
F:\Python314\python.exe ui_tk\run_ui.py --base http://127.0.0.1:8899

# 指定启动页
F:\Python314\python.exe ui_tk\run_ui.py --page scan

# 无窗口自检（校验导入链、Tk 可用性、页面契约、后端目录探测）
F:\Python314\python.exe ui_tk\run_ui.py --self-test

# 关闭自动拉起后端（想自己手动起时用）
F:\Python314\python.exe ui_tk\run_ui.py --no-backend
```

### 两种启动方式

| 方式 | 谁起后端 | 说明 |
|------|----------|------|
| `python backend/app.py` | **主程序自己**（同进程 uvicorn） | 正式启动方式：起 uvicorn + 网络监控 + 文件守护 + 自保护，然后开 Tk 界面。后端与界面在**同一个进程**里。 |
| `python ui_tk/run_ui.py` | **界面自己拉**（子进程） | 单独跑界面时用。界面探测后端，没在跑就用下面的命令拉一个。 |

#### 方式二（单独跑界面）拉后端的命令

刻意用 `-m uvicorn` 而不是 `python app.py`：

```powershell
python -m uvicorn app:app --host 127.0.0.1 --port 8899 --log-level warning
```

原因：`app.py` 的 `__main__` 现在会启动 **Tk 界面本身**。若用 `python app.py`
去"起后端"，等于又开一个完整的主程序（第二个 Tk 窗口 + 第二套防护）。
走 `-m uvicorn app:app` **不执行 `__main__`**，得到的是纯 API 后端。

| 行为 | 说明 |
|------|------|
| 自动拉起 | 可在设置页关掉（偏好存 `%LOCALAPPDATA%\Andun\ui_prefs.json`） |
| 主程序启动时 | `app.py` 会把 `auto_start_backend` 强制置为 False —— 后端就是本进程，不能再去拉第二个 |
| 只连接不接管 | 后端若已在跑（你自己起的/主程序在跑），UI 只连接，**绝不停止它** |
| 只停自己的 | 侧栏「停止后端」仅对本界面拉起的进程有效 |
| 退出时 | 默认**不关**后端（关掉后端等于停止防护）；可在设置页改成关闭 |
| 失败可见 | 启动失败、就绪超时、进程早退都会在状态条报出，并给出日志路径 `%LOCALAPPDATA%\Andun\data\logs\ui_backend.log` |
| 定位 | 后端目录自动按 `ui_tk` 的兄弟目录探测；找不到时设置页可手动指定 |

手动启动一个纯后端（想让界面单独连它时）：

```powershell
cd H:\Caelire\backend
F:\Python314\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8899
```

### 关于 `.bat` 启动器（PowerShell 曾一度不可用）

> **现状更新：`pwsh` 已恢复正常**（本会话前段它一直以 `0xC0000142`
> `STATUS_DLL_INIT_FAILED` 启动失败，现已可用，`py_compile` 与自检都能直接从
> PowerShell 跑）。所以下面这段是**历史记录 + 备用手段**，不再是必须的绕行方案。

故障期间的已知诱因见 `ISSUES.md` 第四节：火绒的 `hramsi.dll` 注册为系统唯一
AMSI Provider，其 `AmsiScanBuffer` 触发访问违例会打崩 PowerShell 进程。
PowerShell 在启动时初始化 AMSI，**而 cmd.exe 与资源管理器双击不走 AMSI**，
因此当时靠这两个 `.bat` 绕开：

| 文件 | 用途 |
|------|------|
| `ui_tk\自检.bat` | 不开窗口跑自检，结果留在屏幕上（推荐先跑这个） |
| `ui_tk\启动界面.bat` | 启动图形界面 |

双击即可，无需 PowerShell。两者都会先探测 Python 是否可用，并在退出时
`pause` 保留输出。

> ⚠️ **维护这两个 `.bat` 时必须保持内容为纯 ASCII。**
> 踩过的坑：`.bat` 用 UTF-8 保存、中文 Windows 的 cmd 按 GBK(cp936) 读取时，
> 中文字节会变乱码；更严重的是在**文件中间**执行 `chcp 65001` 会让 cmd 按字节
> 偏移重读文件、从半截行开始解析，于是报出一堆碎片命令
> （`on.exe"`、`PY`、`~dp0run_ui.py"`、`VEL"`），完全无法调试。
> 所以：**不要写中文，也不要写 `chcp`**。中文只放在文件名里（文件名是 UTF-16，
> 不受代码页影响）。

---

## 设计约定

**配色**：直接取 `backend/frontend/index.html` 的 CSS 变量与
`ai_learning_results/Tkinter_GUI/20260725_dashboard.md` 的设计 token，
保证新旧界面是同一套视觉语言：底色 `#07070a`、卡片 `#13131c`、强调 `#00d9c0`、
危险 `#ff4d6d`，三级文字灰度构建层级。

**为什么全用 `tk` 而不是 `ttk`**：Windows 上 ttk 控件由系统主题绘制，
`background` 基本被忽略，暗色主题做不干净。全量 `tk` + 显式 `bg`/`fg` 是唯一
可靠做法。卡片边界用「外层 Frame 填描边色 + 内层填卡片色 + 1px padding」模拟，
不用 Canvas 画假圆角（高 DPI 下会糊）。

**线程模型**：网络请求一律走 `api.run_async()` → 后台 daemon 线程执行，
结果通过 `widget.after(0, ...)` 回到主线程。**Tk 不是线程安全的**，所有控件操作
必须发生在主线程，`run_async` 是唯一入口。

**定时器生命周期**：自带 `after` 循环的组件（`PulseDot`）实现 `stop()` 并在
`destroy()` 中自动调用；页面用 `Page.every()` 注册周期任务，切页时 `on_hide()`
统一 `cancel_timers()`。不这么做的话，切走页面后回调仍会更新已销毁控件并抛
`TclError`——这是 Tkinter 最常见的坑，项目设计笔记里也记了这条。

**离线优先**：所有 API 调用收敛成 `ApiResult(ok, data, error, status)`，
网络异常不抛给调用方。后端不在跑时，界面显示「后端未连接」而不是崩掉。
切换防护模块失败时**回滚 UI 开关**，不让界面停在服务端没接受的状态。

---

## 当前实现范围

已完成 **12 个页面**：

| 页面 | 内容 |
|------|------|
| **概览** `overview` | 防护状态（呼吸点）、8 项统计卡、6 个防护模块开关（乐观更新+失败回滚）、待决威胁列表（对接 15 秒决策闸门）、最近活动 |
| **病毒扫描** `scan` | 快速/全盘/自定义（目录选择器）、自绘进度条、900ms 轮询任务状态、取消任务、结果列表（规则/等级/引擎/路径/SHA256） |
| **隔离区** `quarantine` | 列表、单个还原/删除、批量还原/删除，危险操作二次确认 |
| **垃圾清理** `clean` | 扫描（六类垃圾）、分类勾选（默认全选）、执行清理、扫描中可取消、清理历史 |
| **电脑优化** `optimize` | 健康评分 + 体检项、一键优化、内存释放、启动项管理（禁用可逆）、第三方服务启动类型（系统服务只读不展示） |
| **安全工具** `tools` | 14 个工具区块，见下 |
| **数据恢复** `recovery` | 快照监控启停、监控目录增删、文件列表 → 历史版本浏览、还原（走 `jobs` 可取消+进度）、删除版本、保留策略设置 |
| **规则管理** `rules` | 规则列表（启停/删除）、新增（类型/动作/模式/描述 + 实时预览）、模板套用、JSON 导入导出 |
| **历史记录** `history` | 检出统计（按引擎/按类型带比例条）、病毒家族 Top10、关键词检索、清空记录 |
| **引擎启动** `engine` | 引擎概览、防护模块开关、云查杀优先级、深度引擎状态、ETW 启停、AMSI 注册/注销、辅助功能总览 |
| **日志报告** `logs` | 威胁日志与扫描日志合并视图、按类型过滤、清空日志 |
| **设置** `settings` | **后端服务控制**（启动/停止/指定后端目录/自动拉起与退出策略）、后端地址切换、引擎信息、特征库统计、系统健康 |

### 安全工具页明细（14 个区块）

- **网址安全检查** —— 输入即查，显示等级 / 命中原因 / 家族
- **网址名单管理** —— 阻断名单与白名单并排展示，可增删；`hosts` 写入/撤销（二次确认）
- **邮件·文本钓鱼检测** —— 本地启发式：钓鱼话术、可疑链接、高危附件名
- **云样本多引擎比对** —— 选文件上传（multipart），本地算 SHA256/MD5 + 云端哈希研判
- **沙箱分析** —— 选文件后走 `jobs` 异步执行并轮询，可取消；展示判定/风险分/行为
- **网络急救** —— DNS/Ping/互联网/HOSTS/LSP 五项指示灯 + 单项修复 + 一键断网急救
- **系统漏洞修复** —— 走 `jobs` 可取消异步任务带进度；只检测与引导，不擅自装补丁
- **下载防护** —— 开关 + 已扫描/检出计数 + 监控目录增删
- **U 盘与外设管控** —— 可移动盘/已免疫盘、禁用自动播放、禁用 USB 存储（二次确认）
- **增强防护八开关** —— 弹窗拦截 / 注册表监控 / 高危行为阻断 / 进程拦截 /
  **勒索诱捕 / 浏览器保护 / 摄像头保护 / 隐私保护**，各带实时计数

### 唯一有意不实现的功能

| 功能 | 原因 |
|------|------|
| **反 Rootkit 扫描** | `ISSUES.md` 2.1：`anti_rootkit.scan()` 因 `SYSTEM_PROCESS_INFORMATION` 结构体布局错误触发 `0xC0000005`，**`try/except` 抓不到，直接杀死解释器**。路由 `/api/v1/rootkit/scan` 确实存在、`jobs` 也有 `rootkit-scan` 这个 kind，但这个按钮一点就会把整个后端进程带走，绝不能放进 UI。等 `anti_rootkit.py` 修好再放。 |

至此 `tools.html` 原 **19 个工具卡已全部覆盖**（含 4 张统计卡对应的功能）。
仍未做的只是主程序侧能力：系统托盘、开机自启、处置弹窗（原 `decision_popup.js`）。

---

## 已知限制

1. **进度用轮询而非 WebSocket**。后端有 `/ws/progress`，但标准库没有 WebSocket
   客户端，自己实现握手+帧解析不值当（设计笔记也把"Tkinter 接 WebSocket"
   列为待深入学习）。当前扫描进度用 900ms 轮询 `/api/v1/scan/{id}/status`。
2. **观感受限于 Tk**：无圆角、无阴影、无渐变、无透明度。已用描边+分层底色
   尽量贴近原设计，但不会和 WebView2 效果完全一致。
3. **滚动区滚轮用 `bind_all`**：同一时刻只有一个页面可见，所以不冲突；
   若将来同屏放两个滚动区，需要改成按 widget 绑定。
4. **高 DPI**：`run_ui.py` 默认开启 DPI 感知（否则 4K/150% 缩放下界面是糊的），
   并据此调整 `tk scaling`。像素级的 padding 不随缩放变化，因此极高缩放下
   文字会比间距显得略大。可用 `--no-dpi` 关掉。
5. **没有系统托盘/通知**，也没有处置弹窗（原 `decision_popup.js` 的功能），
   待决威胁目前只在概览页里展示。

---

## 验证状态

**已通过自检**（2026-10-11，直接从 PowerShell 运行）。四个阶段全绿：

```
[1/4] 纯逻辑模块（不加载 tkinter）
      [ok] api 工具函数（含边界值）
      [ok] backend 模块（后端目录=H:\Caelire\backend，python=F:\Python314\python.exe，
                         偏好=C:\Users\...\Andun\ui_prefs.json）
[2/4] 加载 tkinter 并创建 Tk 根窗口
      tkinter 导入成功，版本 8.6
      [ok] Tk 8.6，UI 字体 = Microsoft YaHei UI
[3/4] 页面契约与控件构建
      [ok] 12 个页面类契约完整：['clean', 'engine', 'history', 'logs', 'optimize',
                                   'overview', 'quarantine', 'recovery', 'rules',
                                   'scan', 'settings', 'tools']
      [ok] 每个页面可构建并销毁（build() 无异常）
[4/4] 页面生命周期与离线降级
      [ok] OverviewPage on_show/on_hide 正常（周期任务 1 个）
      [ok] ScanPage on_show/on_hide 正常（周期任务 0 个）
      ...（12 个页面全部通过）
自检通过。
```

同时 `python -m compileall ui_tk` 与 `python -m py_compile backend/app.py` 均返回 0。

这覆盖了：导入链、Tcl/Tk 可用性、字体解析、12 个页面的 `build()` 控件构建、
`on_show`/`on_hide` 定时器注册与清空、以及**后端不在时的离线降级路径**
（阶段 4 故意把后端指向死端口 `127.0.0.1:1`，要求全部请求失败但界面不崩）。

⚠️ **仍未做人工点击验证**：自检不打开窗口，因此以下需要肉眼确认——
实际观感与配色、滚动与滚轮、窗口缩放、DPI 缩放下的布局、以及**连上真实后端后**
各页面的数据渲染是否正确（统计数字、扫描进度、隔离区列表、各工具状态）。

工具页 / 优化页 / 恢复页 / 规则页尤其需要连后端实测：它们合计涉及 60 多个不同
端点的字段解析，自检只能证明"后端不可用时不崩"，证明不了"字段读对了"。

启动界面：

- `python backend\app.py` —— 主程序启动链（后端与界面同进程，无需另起后端）
- 双击 `ui_tk\启动界面.bat` —— 只跑界面（界面会自己拉起后端进程）

两种方式都确认侧栏显示「后端已连接」与概览页统计数字。
