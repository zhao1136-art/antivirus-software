<div align="center">

# 御天 · Yutian

**一个自己写的 Windows 安全防护套件 —— 从 YARA 规则、ETW 行为监控到内核桥接，全部开源可审计。**

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6?logo=windows&logoColor=white)](#)
[![Python](https://img.shields.io/badge/python-3.14-3776AB?logo=python&logoColor=white)](#)
[![FastAPI](https://img.shields.io/badge/API-FastAPI%20%2B%20WebSocket-009688?logo=fastapi&logoColor=white)](#)
[![YARA](https://img.shields.io/badge/YARA-114%20rule%20files-7B2D8E)](#)
[![Native](https://img.shields.io/badge/native-C%2B%2B%209%20ETW%20providers-5C6BC0)](#)
[![License](https://img.shields.io/badge/license-Apache--2.0-EA6A00)](LICENSE)

</div>

---

## 它是什么

一个**不依赖任何商业杀毒引擎**的 Windows 安全软件。检测层自己写，规则自己挑，误报自己压。

不是 demo：它有 FastAPI 后端（309 个接口）、Tkinter 桌面界面（14 个页面）、
C++ 原生防护层（AMSI / ETW / 注入 / 无文件 / 持久化）、独立实时防护进程，
以及一套带**跨引擎确认**的处置流程。

**它的设计取向很明确 —— 宁可漏，不可滥杀。** 下面「为什么要多一道闸门」那一节讲的就是这个。

## 亮点

| | |
|---|---|
| **114 个 YARA 规则文件** | 分 APT / crimeware / generic / hacktools / ransomware 五类，带**有效鉴别力分级**：字面量不足 8 字节的规则自动降级为「仅告警」，不给它搬走文件的权力 |
| **9 个 ETW provider** | Threat-Intelligence / Kernel-Process / Kernel-File / Kernel-Registry / DNS / PowerShell / WMI / DotNET / Sysmon，29 条行为规则，自带限流与背压 |
| **C++ 原生层** | AMSI Provider、ETW 消费、注入检测、无文件执行、持久化监控。**默认全部用户态**；内核驱动仅有实验性源码，未编译、未签名、不随发布包分发（见 [`backend/driver/README.md`](backend/driver/README.md)） |
| **双层阻拦** | YARA 命中后，**必须至少一个其他引擎也命中**才允许隔离 —— 见下文 |
| **沙箱** | Low 完整性 + 网络阻断 + 嵌套 Job Object + 内存镜像扫描，并且**如实申报能力边界**（绝对路径重定向不支持就是说不支持） |
| **签名校验含目录签名** | WinVerifyTrust 验内嵌签名 → CatRoot 查 `.cat`。大量系统文件是目录签名，只查 PE 里那一段会漏 |
| **完整取证输出** | CRC32 / XXH64 / MD5 / SHA1 / SHA256 / SHA3-256 / BLAKE2b，PE 结构、区段熵、导入表、PDB 路径、IOC |

## 为什么要多一道闸门

2026-10-03 出过一次事故：一条 YARA 规则（`EXE_in_LNK`）在 **514/585 个合法 `System32` 文件**上命中 —— 88% 误报率。当时的处置是「YARA 命中即自动隔离」，于是 **42 个系统文件被搬走**。

那之后处置流程改成了现在这样：

```
YARA 命中
   │
   ├─ 闸门零  规则有效鉴别力 <8 字节？        → 仅告警，不进入处置
   ├─ 闸门一  可信系统文件（签名/目录签名）？   → 仅告警
   ├─ 闸门二  YARA 之外还有引擎点头？          → 没有 → 仅告警（不进决定流程）
   └─ 闸门三  用户决定 / 超时
          │
       隔离
```

**闸门二「跨引擎确认」是关键**：`hash`（特征库）和 `heuristic`（启发式）两者至少一个命中才算数。
**ML 被刻意排除在确认名单外** —— 实测它对 936 个合法系统文件的误报率是 **48%**（两个独立语料一致），
让它参与确认等于闸门失效。ML 现在只作参考信息。详见 [`docs/`](docs/)。

## 快速开始

```bash
# 1) 装依赖
pip install -r backend/requirements.txt

# 2) 起后端（127.0.0.1:8899）
cd backend && python -m uvicorn app:app --host 127.0.0.1 --port 8899

# 3) 起桌面界面（Tkinter，不需要浏览器）
cd ui_tk && python run_ui.py
```

> 界面自检：`cd ui_tk && python run_ui.py --self-test` —— 无窗口验证 14 个页面能否构建、定时器是否正确释放。

**打包**：`backend/御天.spec`（PyInstaller onedir，当前发布方式）

> `backend/御天_onedir.spec` 是 2026-10-03 的旧版，**已失效**（引用了已删除的
> bingduku 目录、且不含 ui_tk 界面检查），构建会失败。请一律使用 `御天.spec`。

## 目录结构

```
backend/                  ★ FastAPI 主服务
├── app.py                   API 网关（309 个接口）
├── engine/                  检测引擎（YARA / 启发式 / ML / 沙箱 / 云查杀 / 取证）
│   ├── yara_rules/          YARA 规则集（114 个 .yar）
│   ├── native_guard/        C++ 原生防护层（AMSI / ETW / 注入 / 无文件 / 持久化）
│   └── capa_rules/          capa 行为规则
├── frontend/                历史 Web 前端（已由 ui_tk 取代，保留作对照）
└── installer/               安装包脚本

ui_tk/                    ★ Tkinter 桌面界面（14 个页面）
├── andun_ui/pages/          overview / scan / quarantine / privacy / lists / tools …
└── run_ui.py                入口 + 无窗口自检

rtguard/                  独立的实时防护进程（可与主程序分离、CPU 可节流）

docs/                     设计文档
├── etw-coverage.md          ETW 覆盖地图（自动生成，含「什么条件下会漏」）
└── sample-report-format.md  样本取证报告格式

tools/                    独立工具
├── sample_analyzer.py       通用样本分析（哈希 / PE / 启发式 / IOC，不出网）
├── sample_analyzer_gui.py   同上，Tkinter 界面；可 PyInstaller 打成免安装 exe
├── signal_score.py          组合信号加权评分（只评分，不处置）+ 校准台
├── collect_fp.py            误报上报汇总 → 指出哪条规则该复核
└── gen_etw_coverage.py      从源码生成 ETW 覆盖地图

ISSUES.md                 已知问题与待办
```

## 已知限制（诚实清单）

这些不是待办，是**架构性的边界**，写出来是为了不让人误以为它们被覆盖了：

- **没有可用的内核驱动** —— 默认全用户态。绕过 ETW 的手法（直接系统调用等）看不到。
  `backend/driver/` 里有一份 WDM 驱动**实验性源码**（17 个文件），但**从未成功编译、
  未签名、不随发布包分发**，也没有任何默认启用路径；在实体机上加载未签名驱动会
  直接蓝屏甚至无法开机。详见 [`backend/driver/README.md`](backend/driver/README.md)。
- **ETW 限流是无差别的** —— `Kernel-File` 120 事件/秒、`Kernel-Process` 150/秒。超过就丢，**连已判定命中的事件也一起丢**。解压大压缩包、批量编译时必然触发。详见 [`docs/etw-coverage.md`](docs/etw-coverage.md)。
- **Threat-Intelligence provider 只对签名杀软开放** —— 未签名构建里那 9 条注入类规则一条都不会触发。状态里 `enable_ok` 字段可查。
- **`Kernel-File` 只听创建/重命名** —— 看不到写入内容，也看不到删除。
- **沙箱不是真 CoW** —— `engine: copy` 只隔离样本自身及其同目录，样本对 `C:\Windows\...` 的绝对引用照旧打到真实系统。
- **ML 已按设计保留"仅参考"地位** —— 现在有自训练的 PE 模型（ONNX + LightGBM 两套产物，
  在 4910 个本地样本上 holdout AUC 0.9997 / 误报率 0.13%），但**刻意不给处置权**：
  数据来自本机、规模有限，泛化能力未经验证，ML 的 action 固定为 `alert`。
  详见 `backend/engine/models/features.json` 里的实测指标与 `tools/train_pe_model.py`。
- **WMI 创建进程（T1047）未覆盖** —— WMI provider 只听持久化三件套（事件 11/22/23）。

## 相关项目

- [**yutian-guardian-ai**](https://github.com/zhao1136-art/yutian-guardian-ai) —— 二进制转灰度图 + 轻量 CNN + OOD 四态融合的 AI 检测分支
- [**memory-optimizer**](https://github.com/zhao1136-art/memory-optimizer) —— 同作者的 C 语言内存优化工具

## 许可

**禁止商业使用。**

本项目采用 [PolyForm Noncommercial License 1.0.0](LICENSE)。

- **允许**：个人学习、研究、实验、业余项目；教学、公益、公共研究、政府部门等非商业组织使用。
- **不允许**：任何商业用途 —— 包括但不限于集成进商业产品、做成 SaaS 或收费服务、
  为企业内部商业运营提供支持。

本仓库另外包含第三方组件，各自保留原有许可：capa 规则（Apache-2.0）、ClamAV（GPLv2）、maltrail 与 YARA 规则包等。这些部分**不受本许可约束**，以各自原始许可为准。


> 本项目为个人项目，按「现状」提供，不附带任何担保。

