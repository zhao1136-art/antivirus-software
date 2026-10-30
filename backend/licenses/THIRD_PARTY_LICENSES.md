# 第三方组件与许可声明（THIRD PARTY LICENSES）

本文件随「御天」发布包一同分发，见同目录下的许可全文：

| 文件 | 内容 |
|---|---|
| `GPL-2.0.txt` | GNU General Public License v2.0 全文 |
| `Apache-2.0.txt` | Apache License 2.0 全文 |
| `BSD-3-Clause.txt` | BSD 3-Clause 许可全文 |
| `MIT.txt` | MIT 许可全文 |
| `SOURCE_OFFER.txt` | GPL 组件的源码获取方式（书面要约） |

---

## 一、随发布包分发的第三方二进制

| 组件 | 版本 | 许可 | 分发形态 |
|---|---|---|---|
| **ClamAV**（`clamscan.exe`、`libclamav.dll` 及其依赖 DLL） | 1.5.3 | **GPL-2.0** | 以**独立子进程**调用（`subprocess.run`），不链接、不加载其 DLL |
| **OpenSSL**（`libssl-3-x64.dll`、`libcrypto-3-x64.dll`） | 3.6.3 | **Apache-2.0** | 动态库，随 ClamAV/curl 依赖分发 |
| **MinGW-w64 运行时**（`libgcc_s_seh-1.dll`、`libstdc++-6.dll`、`libwinpthread-1.dll`） | — | **GPL-3.0 + GCC Runtime Library Exception 3.1** | 动态库 |
| **YARA**（`libyara.dll`，本项目自行构建） | 4.5.5 | **BSD-3-Clause** | 通过 ctypes 调用 |
| **PE-sieve**（`pe-sieve64.exe`） | 0.4.1.1 | **MIT** | 独立子进程调用 |
| **Microsoft Visual C++ 运行时**（`msvcp140*.dll`、`vcruntime140*.dll`、`concrt140.dll`） | — | Microsoft 可再分发组件条款 | 动态库 |

### ClamAV（GPL-2.0）—— 义务说明

- **版权**：Copyright (C) 2007-2026 Cisco Systems, Inc. 及 ClamAV 项目贡献者。
- **二进制未经修改**：包内的 `clamscan.exe` / `libclamav.dll` 为 ClamAV 1.5.3
  官方发行版原样拷贝，未做任何改动、未打补丁。
- **调用方式**：本项目**不链接** `libclamav.dll`，也不通过 `ctypes` 加载它；
  仅以 `subprocess.run([clamscan.exe, "--no-scan-archive"…, path])` 形式调用
  独立可执行文件。ClamAV 与「御天」之间是**独立进程 + 命令行参数**的调用关系。
- **源码获取**：见 `SOURCE_OFFER.txt`。
- **已移除的组件**：`freshclam.exe`、`libfreshclam.dll`、`sigtool.exe`
  （共约 56 MB）经核查**没有任何代码调用**，已从发布包中删除，以减小分发体积
  与第三方代码面积。

### OpenSSL（Apache-2.0）

Copyright 1998-2026 The OpenSSL Project Authors。附 `Apache-2.0.txt`，
并保留其版权与许可声明。

### MinGW-w64 运行时（GPLv3 + GCC Runtime Library Exception）

`libstdc++-6.dll` 等来自 MinGW-w64 工具链，受 **GCC Runtime Library Exception
3.1** 保护：允许以任意许可的软件动态链接使用这些运行时库，不使本软件整体
受 GPL 约束。例外条款全文见：
<https://www.gnu.org/licenses/gcc-exception-3.1.html>

（本仓库未内置该例外条款的全文，若发行审核需要，请将该页面内容一并加入
本目录。）

### YARA（BSD-3-Clause）

Copyright (c) Victor M. Alvarez 及 YARA 贡献者（VirusTotal / Google）。
本项目使用 YARA 4.5.5 源码自行构建为 `libyara.dll`（构建配方见
`backend/engine/native/yara/BUILD.md`）。附 `BSD-3-Clause.txt`。

### PE-sieve（MIT）

PE-sieve 0.4.1.1，Copyright © 2017-2025 Hasherezade（hashereware.com）。
附 `MIT.txt`。

### Microsoft Visual C++ 运行时

`msvcp140*.dll` / `vcruntime140*.dll` / `concrt140.dll` 属 Microsoft
Visual C++ Redistributable，按 Microsoft 的可再分发条款随应用分发，
**不属于**开源软件。

---

## 二、随包分发的数据 / 情报（非代码）

| 数据 | 许可 | 署名 |
|---|---|---|
| **maltrail** 静态 IOC（`engine/data/ioc/url_extra.u64`、`ip_extra.u64`，约 106 万恶意域名 + 2.3 万 IP） | **MIT** | Copyright (c) 2014-2026 Maltrail developers (<https://github.com/stamparm/maltrail>) |
| **IPsum**（`engine/data/ioc/c2_ip.u64` 中的约 1.99 万高置信 IP） | **The Unlicense（公有领域）** | 由 stamparm 从 30+ 公开黑名单聚合，无署名要求 |
| **abuse.ch Feodo Tracker**（`c2_ip.u64` 中的在线 C2 IP） | **CC0 1.0** | abuse.ch（可选，需 Auth-Key 的 URLhaus/ThreatFox 未使用） |
| **YARA 规则集**（`engine/yara_rules/`，133 条） | 规则内自带 `TLP:CLEAR` 等元数据，来源为公开规则仓库（MIT 等） | 各规则 `meta.author` / `meta.source` 字段 |

许可全文：MIT 见 `MIT.txt`；The Unlicense 见 <https://unlicense.org/>；
CC0 1.0 见 <https://creativecommons.org/publicdomain/zero/1.0/>。

---

## 三、仅在开发期使用、**不随发布包分发**

| 组件 | 许可 | 说明 |
|---|---|---|
| **C2IntelFeeds** | **CC BY-NC-SA 4.0**（NonCommercial + ShareAlike） | **不得商用分发**。仅本机开发/研究使用，已在 `.gitignore` 中排除，发布包内不含。 |
| EMBER 数据集 / 训练素材 | 各自条款 | 仅用于本地训练模型；发布包只含训练产物 `pe_model.onnx` / `pe_model.txt` |
| `torch` / `onnxruntime` / `scipy` / `sklearn` / `tensorflow` | 各自许可 | 已在 `御天.spec` 的 `excludes` 中排除，不进入发布包 |

---

## 四、如何核验

```powershell
# 包内 ClamAV 版本
backend\engine\native\clamscan.exe --version
# 包内 PE-sieve 版本
backend\engine\native\pe-sieve64.exe /version
```

---

## 五、免责声明

本清单由项目维护者按代码与二进制实际存量整理，**不构成法律意见**。
若计划商业发行，请由法务确认下列事项，特别是：

1. 随包分发 **GPLv2 的 ClamAV 二进制**是否符合你的发行模式
   （本项目的调用方式是独立子进程，属"聚合"形态，义务最轻；
   但**仍属分发 GPL 程序**，须附许可全文并提供源码获取方式）。
2. 是否需要在安装器中放置一次性的许可展示/同意页。
3. GCC Runtime Library Exception 全文是否需要内置。

如需彻底规避 GPL 相关义务，可改为**不随包分发 ClamAV**：
`engine/deep_analyzer.py` 在找不到包内 `clamscan.exe` 时会回退到
系统 PATH 中的 `clamscan`，因此仅删除包内 ClamAV 二进制即可，
**无需任何代码改动**。
