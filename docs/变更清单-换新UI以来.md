# 换新 UI 以来的全部改动

> 生成于 2026-10-31，基于 `H:\Caelire` git 仓库（`main` 分支）。
>
> **"换新 UI" 指：主程序界面从 WebView2/frontend 换成 Tkinter（`ui_tk/`）。**
> 边界由提交 `8f11cf7`(2026-10-16) 界定 —— 它的提交信息已写明"主程序界面已从
> WebView2 整体换成 ui_tk/"。
>
> **范围：`8f11cf7^..HEAD`，共 33 次提交，2026-10-16 → 2026-10-31。**

---

## 总览

| 指标 | 数值 |
|---|---|
| 提交数 | **33** |
| 变更文件 | **328** |
| 新增行 | **+32,959** |
| 删除行 | **−43,791** |

### 按目录

| 目录 | 文件数 | 新增 | 删除 | 说明 |
|---|---:|---:|---:|---|
| `backend/` | 75 | 17,986 | 1,295 | 主要工作量：ML、驱动、情报源、审查修复 |
| `ui_tk/` | 23 (+2) | 9,338 | 0 | **新 Tkinter 界面整体入库** |
| `tools/` | 10 | 4,288 | 0 | 10 个新工具 |
| `docs/` | 3 (+1) | 719 | 0 | 4 份新文档 |
| `rtguard/` | 208 | 44 | **42,103** | **整个目录删除**（死副本） |
| 根 / `.github` | 4 | 357 | 393 | 含 `logo_splash.py` 删除 |

---

## 一、新 Tkinter 界面（`ui_tk/`）

| 提交 | 内容 |
|---|---|
| `8f11cf7` | 桌面决策窗口配色对齐新 UI（旧火绒风 `#1b1b1d/#131315/#e0483c` → `#13131c/#0e0e14/#00d9c0/#ff4d6d`），4 处内联色值提成具名常量 |
| `8a2be6b` | **删除网页威胁弹窗** `frontend/decision_popup.js`（−294 行）+ 移除 16 个页面里的引用；决策通道改为 overview 页待决列表 + `desktop_prompt.py` |
| `635cd3a` | 补回两处丢失入口：①设置页「实时防护·CPU 节流」卡片（低5%/中10%/高15% + 6 项统计 + 3s 轮询）②设置页「退出程序」卡片；`api.py` 补 `rtguard_*`/`shutdown`/`privacy_*`/`sandbox_*` 共 13 个方法 |
| `02a7a60` | 新建 `pages/privacy.py`（第 13 页）；沙箱报告补 `isolation` / `memory_scan` 两段；修 `LEVEL_TEXT` 缺 clean/unknown 映射；修一个 `len(lines)<=2` 的自引入 bug |
| `0731cb2` | 新建 `pages/lists.py`（第 14 页「名单管理」）；后端补 `remove_from_whitelist()` + `POST /api/v1/process-guard/whitelist-remove`；`api.py` 补 9 个方法 |
| `9c5c19b` | **`ui_tk/` 整体入库**：26 文件 / 395 KB，含 `run_ui.py`、`andun_ui/{theme,widgets,backend,api,app}.py`、14 个页面、README、2 个 .bat |
| `e823f3c` | 删掉 `engine.html` 启发式引擎静态卡（`status='static'`、`action='none'` 的纯装饰卡） |

**`ui_tk/` 新增的 23 个文件**：`run_ui.py`、`README.md`、`启动界面.bat`、`自检.bat`、
`andun_ui/{__init__,api,app,backend,theme,widgets}.py`、`pages/{__init__,clean,engine,history,lists,logs,optimize,overview,privacy,quarantine,recovery,rules,scan,settings,tools}.py`

---

## 二、检测引擎

| 提交 | 内容 |
|---|---|
| `01b0c8d` | **双层阻拦**：YARA 命中后必须至少再有一个引擎也命中，才允许隔离 |
| `c47f5a1` | **ML 误报率实测 48% → 撤掉它的处置权**；修掉"闸门二"的自我确认漏洞 |
| `e18af9e` | 组合信号加权评分（只评分，不做处置） |
| `f4b22d3` | ETW 覆盖地图：从原生层源码自动生成「能看见什么 / 什么条件下漏」 |
| `1e66cf0` | 实时防护接线 + 隔离走正规通道 + 删除 rtguard 死副本；YARA/ML 加预算 |
| `0c458b5` | PE 特征提取向量化：**1.89 → 7.5 MB/s（4.0x）**，特征完全等价 |
| `71f5e56` | **机器学习落地**：自训练 PE 模型 + ONNX 导出 + `features.json` 契约 |
| `703f5dc` | 重训：排除训练缓存，修掉良性集里混入恶意样本的**标签污染** |
| `274fa20` | 修 ML 检出被静默丢弃（返回字典缺 `verdict` 键） |
| `0907f94` | ML 四项 P2 + IOC 哈希从 32 位有效熵升级到 **blake2b-64**（含国内镜像回退） |
| `a247579` → `c753461` | 扫描扩展名对齐 + SFX 归档识别 → **随后被 revert** |

**新增后端模块**：`engine/ember_onnx.py`(+280)、`engine/ember_model.py`(+118/−17)、
`engine/cross_check.py`(+221)、`engine/ioc_index.py`(+210)、`engine/andun_client.py`(+151)、
`engine/ml_scanner.py`(+282/−56)、`engine/tray_icon.py`(+113/−13)、`engine/models/features.json`(+4,809)、
`engine/models/pe_model.txt`(+4,548)

---

## 三、内核驱动（新增）

commit `729b6f0` 标注为"驱动**实验性**"。整个驱动源码树是本期新增的：

`backend/driver/andun_driver/` —— **14 个文件 / 160 KB**

| 文件 | 大小 | 文件 | 大小 |
|---|---:|---|---:|
| `rootkit_scan.c` | 21.7 KB | `object_callback.c` | 12.7 KB |
| `network_filter.c` | 19.6 KB | `process_callback.c` | 12.7 KB |
| `rule_engine.c` | 15.2 KB | `self_protect.c` | 10.7 KB |
| `andun.h` | 14.5 KB | `registry_callback.c` | 307 行 |
| `file_filter.c` | 13.6 KB | `device_control.c` | 324 行 |
| `event_queue.c` | 244 行 | `response.c` | 169 行 |
| `driver_main.c` | 206 行 | `build.bat` | 133 行 |

---

## 四、威胁情报源

| 提交 | 内容 |
|---|---|
| `27e6092` | **maltrail** 第三方 IOC：106 万恶意域名 + 2.3 万 IP |
| `fb8586f` | 可商用情报源接入（abuse.ch Feodo）+ YARA 规则集评估结论 |
| `12694bd` | 情报源替代：接入 **IPsum**（公有领域） |
| `729b6f0` | **C2 情报源收敛** + 第三方许可合规 + 驱动实验性标注 |

**新增**：`tools/import_feeds.py`、`tools/build_ioc_index.py`、`backend/licenses/{GPL-2.0.txt, Apache-2.0.txt, THIRD_PARTY_LICENSES.md}`

---

## 五、审查修复

| 提交 | 内容 |
|---|---|
| `6ec64bc` | **审查清单 A 组：8 项**（接口 500 / 扫描覆盖 / 打包配置 / 静默失效） |
| `ae2f4e7` | **审查清单 B 组：7 项**（配置持久化 / 闸门二 / 扫描失败记账 / 令牌下发 / 自保护） |
| `096a023` | 修打包版"无法启动扫描"：日志写入失败导致扫描请求 500 |
| `7e477b7` | 去掉本地令牌，前端直连后端（改为只挡外部网页的跨源请求） |

---

## 六、工具与文档

**`tools/` 新增 10 个**：
`sample_analyzer.py`、`sample_analyzer_gui.py`、`file_report.py`、`file_report_gui.py`、
`train_pe_model.py`、`signal_score.py`、`gen_etw_coverage.py`、`collect_fp.py`、
`import_feeds.py`、`build_ioc_index.py`

**`docs/` 新增 4 份**：`etw-coverage.md`、`sample-report-format.md`、
`threat-advisory-2026-10-17.md`、`IOC数据源方案.md`

| 提交 | 内容 |
|---|---|
| `c166ccd` | 新增通用样本安全分析工具 + 卡饭格式报告模板 |
| `07bf184` | **误报反馈闭环**：隔离区「这是误报」按钮 + 上报接口 + 汇总工具 |
| `67f1733` | README 重写：首屏 + 诚实限制清单 + 数字全部实测核对 |

---

## 七、版本与清理

| 提交 | 内容 |
|---|---|
| `68cb38f` | 版本号统一：软件 1.1.0 / 病毒库 1.26.10.24 |
| `a456112` | 版本名称改为「正式版」(1.1.0) |
| `c8d0759` | 工作区清理：收入正当改动 + 情报/构建产物挡在库外 |

**删除的东西**：`rtguard/` 整个目录（208 文件 / −42,103 行，死副本）、
`backend/frontend/decision_popup.js`(−294)、`backend/logo_splash.py`(−280)

---

## 八、未提交的改动（截至 2026-10-31）

| 状态 | 文件 | 说明 |
|---|---|---|
| `M` | `backend/御天.spec` | **+16 / −10**：纠正 pywin32 排除项。原注释说"别排除 pythoncom/win32com 否则静默失效"，实测该判断**不成立** —— 本机根本没装 pywin32，两条使用路径都有无依赖回退（`usb_scanner` 走轮询、`startup_scanner` 手工解析 .lnk）；反之去掉 excludes 会让 PyInstaller 的 pywin32 钩子在隔离子进程里崩掉 |
| `M` | `data/guard_days.json` | 运行时累积数据（防护天数） |
| `??` | `android/` | 未跟踪的 Android 端工程 |
| `??` | `_tmp/` | 临时调试脚本（本次分析产生） |

---

## 附：33 次提交完整清单

```
2026-10-16 8f11cf7 桌面决策窗口配色对齐新的 Tkinter UI
2026-10-16 8a2be6b 删除网页威胁弹窗
2026-10-17 635cd3a tk UI 补回两处丢失入口 + 补客户端方法
2026-10-17 02a7a60 tk UI 补齐隐私防护页 + 沙箱报告补两段关键展示
2026-10-17 0731cb2 加白名单/黑名单管理（第 14 页）+ 补后端缺口
2026-10-17 9c5c19b 把 Tkinter 界面 ui_tk/ 整体入库
2026-10-17 e823f3c 删掉 engine.html 启发式引擎静态卡
2026-10-17 01b0c8d 加双层阻拦
2026-10-17 c47f5a1 ML 误报率 48% -> 撤掉处置权；修闸二自我确认漏洞
2026-10-17 c166ccd 新增通用样本安全分析工具 + 卡饭报告模板
2026-10-17 a247579 后端完善：扫描扩展名对齐 + SFX 归档识别
2026-10-17 c753461 Revert "后端完善：扫描扩展名对齐 + SFX"
2026-10-17 07bf184 误报反馈闭环
2026-10-17 f4b22d3 ETW 覆盖地图
2026-10-17 e18af9e 组合信号加权评分：只评分，不做处置
2026-10-18 67f1733 README 重写
2026-10-24 1e66cf0 安全修复：实时防护接线 + 隔离走正规通道；YARA/ML 加预算
2026-10-24 68cb38f 版本号统一：软件 1.1.0 / 病毒库 1.26.10.24
2026-10-24 a456112 版本名称改为「正式版」(1.1.0)
2026-10-25 0c458b5 性能：PE 特征提取向量化（4.0x）
2026-10-25 71f5e56 机器学习落地：自训练 PE 模型 + ONNX 导出
2026-10-25 703f5dc 重训：排除训练缓存，修掉标签污染
2026-10-25 27e6092 黑名单扩容：接入 maltrail
2026-10-25 fb8586f 可商用情报源接入（abuse.ch Feodo）+ YARA 规则集评估
2026-10-25 12694bd 情报源替代：接入 IPsum
2026-10-25 274fa20 修复：ML 检出被静默丢弃
2026-10-25 096a023 修复打包版"无法启动扫描"
2026-10-30 6ec64bc 审查清单 A 组：8 项修复
2026-10-30 ae2f4e7 审查清单 B 组：7 项修复
2026-10-30 729b6f0 第三方许可合规 + 驱动实验性标注 + C2 情报源收敛
2026-10-30 0907f94 ML 四项 P2 + IOC 哈希 blake2b-64
2026-10-31 c8d0759 工作区清理
2026-10-31 7e477b7 去掉本地令牌，前端直连后端
```
