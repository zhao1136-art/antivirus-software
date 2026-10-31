# 威胁情报 IOC 数据源方案（只取清单，不下样本本体）

> 写于 2026-10-23。**本方案不含任何恶意文件本体**，只规划 URL / 域名 / IP / 文件哈希
> 四类**纯文本**情报的获取、归一化、落盘与接入方式。
> 状态：**待评审，尚未下载任何数据。**

---

## 0. 目标

给御天补一条**外部情报输入**，用于三件事：

1. **命中归因** —— 扫到的 URL/IP/哈希来自哪个家族、哪类威胁
2. **误报校验** —— 命中是否落在已知正常集合里
3. **ML / YARA 标注** —— 给样本与规则打家族标签

明确**不做**的：

- 不下载恶意样本本体（`MalwareBazaar` 只取哈希元数据，不取 `file`）
- 不接入需要提交样本的沙箱
- 不做高频轮询（尊重源方条款）

---

## 1. 现状盘点（已核实）

### 1.1 已有的东西

| 组件 | 位置 | 能力 |
|---|---|---|
| IOC 下载器 | `engine/signature_downloader.py` | `SOURCES` 注册表 + `download_and_import(source, limit)` |
| 同源情报匹配 | `engine/huorong_intel.py` | 内容签名（原生 Aho-Corasick）+ URL blocklist + 分类查询 |
| 火绒 IOC 产物 | `H:\Caelire\huorong_extract\out\huorong_url_iocs.csv` | **85,035 条** URL IOC |
| 特征库 | `engine/signature_manager.py` | 哈希查库 |

### 1.2 已经发现的问题

**`signature_downloader.py` 的 docstring 与实现不一致：**

```
docstring 声称： 支持 ESET IOC, URLhaus, PhishTank, Blocklist.de
download_and_import 注释声称：source: "all" | "eset" | "urlhaus" | "phishtank" | "blocklist"

实际 SOURCES 注册表只有：
    eset      -> api.github.com/repos/eset/malware-ioc
    blocklist -> lists.blocklist.de/lists/all.txt
```

即 **`urlhaus` 和 `phishtank` 根本不存在**。调用 `download_and_import(source="urlhaus")`
会走 `else` 分支返回 `未知数据源: urlhaus`。这是"注释有、代码没有"，必须
**要么补齐、要么删掉注释**——否则调用方会静默拿到错误结果。

### 1.3 缺失的东西

- 没有统一的 **IOC 归一化 schema**（现在每种源各自为政）
- 没有去重与来源合并（同一个 URL 可能来自 3 个 feed）
- 没有 `first_seen` / `last_seen` / `confidence` 字段
- 没有增量更新机制（全量重拉）
- 没有**家族标签**字段（归因靠猜）

---

## 2. 数据源清单

> **置信度** 说明：`高` = 长期稳定公开的静态文本；`中` = 公开但需确认当前是否要鉴权；
> `待验证` = 只从文档推断，未经核实。
>
> ⚠️ **abuse.ch 自 2024 年起逐步要求 Auth-Key**，`downloads/` 静态文件是否仍免鉴权
> **必须在运行时确认**。所以执行计划第 1 步是**连通性探测**，不是直接写库。

### 2.1 推荐优先接入（纯文本、字段明确）

| # | 源 | 内容 | 端点 | 格式 | 鉴权 | 置信度 |
|---|---|---|---|---|---|---|
| 1 | **URLhaus** (abuse.ch) | 恶意 URL | `https://urlhaus.abuse.ch/downloads/csv_recent/` | CSV | 可能需 Key | 中 |
| 2 | **ThreatFox** (abuse.ch) | IOC + **家族标签** | `https://threatfox.abuse.ch/export/csv/recent/` | CSV | 可能需 Key | 中 |
| 3 | **Feodo Tracker** (abuse.ch) | 僵尸网络 C2 IP | `https://feodotracker.abuse.ch/downloads/ipblocklist.csv` | CSV | 可能需 Key | 中 |
| 4 | **SSLBL** (abuse.ch) | 恶意 SSL 证书 / IP | `https://sslbl.abuse.ch/blacklist/sslipblacklist.csv` | CSV | 可能需 Key | 中 |
| 5 | **OpenPhish** | 钓鱼 URL | `https://openphish.com/feed.txt` | 纯文本，一行一条 | 无 | 高 |
| 6 | **ESET malware-ioc** | 哈希 + 家族 | `https://api.github.com/repos/eset/malware-ioc/contents/` | JSON（GitHub） | 无 | 高（**已接入**） |
| 7 | **Blocklist.de** | 恶意 IP | `https://lists.blocklist.de/lists/all.txt` | 纯文本 | 无 | 高（**已接入**） |

### 2.2 可选补充

| 源 | 内容 | 说明 |
|---|---|---|
| **Spamhaus DROP** | 被劫持网段 | `https://www.spamhaus.org/drop/drop.txt`，公开 |
| **malware-filter** (GitLab) | 聚合的钓鱼/恶意 URL 列表 | 免鉴权，格式规整 |
| **AlienVault OTX** | 脉冲式 IOC | 需免费 API Key，字段丰富 |
| **PhishTank** | 钓鱼 URL | 需 Key；docstring 声称支持但**未实现** |
| **MalwareBazaar** | **仅哈希元数据** | `get_recent` 返回 sha256/md5/家族，**不取 file 字段** |

### 2.3 明确不接的

- 需提交样本的沙箱（VirusTotal 上传、Hybrid Analysis 等）—— 违反"不下样本本体"
- 付费情报源（Recorded Future、GreyNoise 商用版等）
- 来源不明的"AI 安全"聚合站 —— **无法验证数据来源与授权，不接**

---

## 3. 归一化 schema

统一落到 `H:\Caelire\backend\engine\data\ioc\ioc_unified.csv`（附带 `.parquet` 可选）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `ioc_type` | enum | `url` / `domain` / `ip` / `sha256` / `md5` |
| `value` | text | 归一化后的值（域名小写、去尾点；URL 保留完整但小写 scheme/host） |
| `family` | text | 家族标签，空串表示未知 |
| `threat_type` | text | `botnet` / `phishing` / `loader` / `ransomware` / `c2` / `unknown` |
| `source` | text | `urlhaus` / `threatfox` / `feodotracker` / ... |
| `first_seen` | datetime | 源方时间，缺失用抓取时间 |
| `last_seen` | datetime | |
| `confidence` | enum | `high` / `medium` / `low`（按源方分级 + 多源交叉） |
| `raw_ref` | text | 源方原始 ID / 链接，便于回溯 |

**去重规则**：`(ioc_type, value)` 唯一。多源命中时 `source` 用 `;` 合并、
`confidence` 取最高、`family` 取第一个非空。

---

## 4. 落地设计（接进现有代码，不另起一套）

```
engine/
├── signature_downloader.py     ← 扩展 SOURCES（修正 docstring 与注册表不一致）
├── ioc_feeds.py                ← 新增：下载 → 归一化 → 去重 → 落盘
└── huorong_intel.py            ← 复用：URL/domain 匹配 + 原生 AC 加速
```

### 4.1 为什么复用而不是重写

`huorong_intel.py` 已经有：
- `_load_url_blocklist()` / `url_blocklist_match(host, domain)`
- `lookup_url_category(host)`
- 原生 Aho-Corasick（`engine/aho_native`，337 MB/s）

新 IOC 只要**归一化成同样的 URL/domain 形态**，就能直接喂进现有匹配路径，
零额外匹配开销。哈希类走 `signature_manager` 查库。

### 4.2 模块职责划分

| 模块 | 职责 | 不做 |
|---|---|---|
| `ioc_feeds.py` | HTTP 拉取、格式解析、归一化、去重、写盘、增量判断 | 不负责匹配 |
| `signature_downloader.py` | 保留为**特征库**下载（哈希类），IOC 部分委托给 `ioc_feeds` | 不重复实现解析 |
| `huorong_intel.py` | 只读消费归一化后的 IOC 文件 | 不联网 |

### 4.3 增量更新

- 优先用 `ETag` / `Last-Modified` 做条件请求（`If-None-Match`），命中 `304` 就跳过
- 无 ETag 的源：落盘时记 `sha256(content)`，内容未变则不重写
- 每源独立失败隔离：一个源超时不能拖垮整批

### 4.4 落盘位置

```
H:\Caelire\backend\engine\data\ioc\
├── ioc_unified.csv          # 归一化总表
├── manifests\
│   └── urlhaus.json         # 每源的 ETag / 内容哈希 / 抓取时间 / 条数
└── raw\                     # 原样下载（便于追溯，可定期清理）
```

---

## 5. 安全与合规

| 项 | 做法 |
|---|---|
| 只取文本 | 仅下载 CSV / TXT / JSON 元数据；**任何情况下不取样本二进制** |
| 传输 | 强制 HTTPS，校验证书；不跳过校验 |
| 大小限制 | 单源上限 50 MB，超限中止（防被投毒成超大文件） |
| 超时 | 连接 10s / 读取 60s，失败降级跳过该源 |
| 频率 | **1 次/天**（abuse.ch 条款要求，勿高频） |
| 来源标注 | 对外界面/日志注明来源，遵守各源 attribution 要求 |
| 内容不执行 | IOC 是纯文本，不解析为可执行内容；不做 `eval`/`pickle` |
| 落盘不具名执行 | 统一 `.csv`/`.json`，**绝不落成 `.exe`/`.dll`** |

---

## 6. 验证方式（怎么知道它真的能用）

不靠"下载成功"当结论，用三重交叉验证：

1. **交叉验证（最强）**
   用你已有的 **85,035 条火绒 URL IOC** 做基准：同一个恶意 URL 若同时出现在
   URLhaus/ThreatFox 里，两条链路都应该命中。统计**重合率**——重合率高说明
   归一化正确、源可信；重合率为 0 则说明归一化写错了（而不是"源没问题"）。

2. **误报检查**
   拿一份已知正常域名（Alexa/Tranco top-1k 或本机访问过的域名）过一遍匹配，
   **命中数应为 0**。非 0 就是规则或归一化有 bug。

3. **增量正确性**
   连续跑两次：第二次应全部命中 `304`/内容哈希一致，`ioc_unified.csv` 的
   `mtime` 不应变化。

---

## 7. 执行计划（分阶段，每阶段可独立验收）

| 阶段 | 内容 | 产出 | 验收标准 |
|---|---|---|---|
| **P0** | **连通性探测（不下数据）** | 对 2.1 表每个端点发 HEAD / `Range: bytes=0-1023`，记录状态码、`Content-Type`、大小、是否需要鉴权 | 产出"哪些源本机可用、哪些要 Key"的事实清单 |
| **P1** | 修正 `signature_downloader.py` 的不一致 | docstring 与 `SOURCES` 对齐；`urlhaus`/`phishtank` 要么实现、要么从注释移除 | 传非法 source 得到明确错误，不再静默 |
| **P2** | `ioc_feeds.py` 骨架 + 1 个源 | 先只接 **ESET**（已通）与 **OpenPhish**（免鉴权最稳） | 产出符合 schema 的 `ioc_unified.csv`，字段齐全 |
| **P3** | 接入 abuse.ch 系（按 P0 结果） | URLhaus / ThreatFox / Feodo / SSLBL | 需先确认鉴权方式与 Key 申请 |
| **P4** | 与 `huorong_intel` 打通 | URL/domain 复用现有 blocklist 匹配 | 交叉验证重合率有可解释的结果 |
| **P5** | 增量更新 + manifest | 条件请求、失败隔离 | 二次运行不重写 |

**建议先做 P0 + P1**：一个只读探测 + 一处注释/代码不一致的修复，成本极低，
但能避免后面基于错误前提写一堆代码。

---

## 8. 风险与待确认事项

| 风险 | 影响 | 处置 |
|---|---|---|
| abuse.ch 全部改为需 Key | P3 阻塞 | P0 先探明；需免费注册获取 Auth-Key |
| 端点 URL 变更 | 抓取失败 | 每源独立失败隔离 + 日志告警，不能静默 |
| 源方数据被投毒 | 误报上升 | 多源交叉 + `confidence` 分级；单源数据不单独用于自动处置 |
| 本机防护冲突 | 下载被拦 | 本机 Defender 实时保护当前是**关**的、火绒 `HipsDaemon` 在跑；IOC 是纯文本通常不会被拦，但需实测 |
| 合规 | 部分源要求署名/限频 | 已写入第 5 节 |

---

## 9. 一句话结论

**先别写代码。** 先跑 P0 连通性探测，把"哪些源在这台机器上真的能用、要不要 Key"
变成事实，再决定接哪几个——因为 abuse.ch 的鉴权政策在过去两年变过，
按旧文档直接实现大概率白写。
