# rtguard —— 御天实时防护（新版）

从零实现的后台实时防护：目录监控 + 快速扫描 + 隔离 + 托盘。**零第三方依赖**（只用标准库 + 一个自编的 C 匹配器）。

## 为什么重写

老实现（`御天精简版/engine/yara_scanner.py`）是**纯 Python 复刻的 YARA**：每个文件要把缓冲区遍历「模式数」次（166 条规则 / 2172 个模式），实测吞吐 **0.145 MB/s**，`scan.log` 里一个 22.5 MB 文件耗时 **141.8 秒**。它自己的 watchdog 反复记录到 `CPU 使用率过高: 100.0%`。

`yara-python` 在 Python 3.14 上没有 wheel，官方 Windows 发行包只有静态 exe、不含 `libyara.dll`，conda-forge / MSYS2 也没有该包 —— 所以这里自己写匹配器。

## 性能

| | 吞吐 | 22 MB 耗时 |
|---|---|---|
| **本项目（原生 Aho-Corasick）** | **337 MB/s** | **0.065 s** |
| 老实现（纯 Python YARA） | 0.145 MB/s | 141.8 s |

端到端（含读盘 + SHA256 + 匹配，8 MB 语料）：**31 MB/s**，相对老实现约 **215 倍**。

匹配器用 **Aho-Corasick 完全 DFA**：扫描开销只与数据长度有关、与模式数量无关。1153 个真实字面量（21584 字节）构建出 16675 节点，构建耗时 0.079 s。

## 架构

```
rtguard\
├── native\
│   ├── matcher.c      Aho-Corasick 完全 DFA（C，约 250 行）
│   ├── matcher.dll    编译产物（约 10 KB）
│   └── build.bat      三步手工构建脚本
├── rtguard\
│   ├── matcher.py     匹配器绑定：原生优先，纯 Python 回退
│   ├── scanner.py     扫描编排：过滤 -> 哈希 -> 字面量匹配 -> 启发式
│   ├── watcher.py     ReadDirectoryChangesW 目录监控
│   ├── quarantine.py  隔离区（异或混淆 + 原子索引）
│   ├── tray.py        托盘图标与通知
│   └── __main__.py    入口
└── （规则）           默认读 ..\backend\engine\yara_rules；也可放 rules/ 或 --rules 指定
```

> 注：原先这里有一份从主项目复制的 `engine\`（含 `engine\yara_rules`），已于 2026-10-24 删除。
> 现在规则默认从主项目 `backend\engine\yara_rules` 读取；如果要把 rtguard 单独拷走，请把规则
> 放到 `rtguard\rules\` 或用 `--rules` 指定，否则启动会报“规则目录不存在”。

## 构建 matcher.dll

```
native\build.bat
```

**注意：不能一步 `gcc -shared`。** 本机环境下 gcc 的驱动进程无法派生 `as`/`ld`（管道受限），表现为「零输出 + exit 1」；但 `cc1`、`as`、`ld` 单独调用都正常。所以脚本手工驱动三步：

```
gcc -S  ->  as  ->  ld -shared
```

换到没有该限制的机器上，`gcc -O2 -shared -o matcher.dll matcher.c` 一条命令即可。

## 运行

```bash
# 单次扫描（不进监控模式）
python -m rtguard --once "C:\path\to\scan"

# 后台监控（默认只告警，不自动隔离）
python -m rtguard --dirs "C:\Users\me\Downloads" "%TEMP%"

# 确认规则集可信后再打开自动隔离
python -m rtguard --quarantine-on-detect
```

主要参数：`--rules` `--dirs` `--workers 1~4` `--max-mb` `--min-literal` `--no-tray` `--no-native` `--verbose`

## 控制 API（界面在主产品里）

本程序**不再自带前端页面**：档位按钮和实时占用显示都在主产品的 `backend\frontend\guard.html`，
由主产品后端（`backend\app.py` 的 `/api/v1/rtguard/*`）代理到这里的控制 API。

只监听 **127.0.0.1**，端口由 `--control-port`（历史名 `--ui-port`，二者等价）配置，默认 8022：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 状态快照：`level` `target_pct` `actual_pct` `budget_cores` `cores` `stats` `levels`（顶层摊平，同时保留 `throttle`/`stats` 嵌套） |
| POST | `/api/throttle` | body `{"level": "low"\|"medium"\|"high"}`，切换档位并返回新状态；非法档位返回 400 |
| POST | `/api/level` | 同上，历史名，保留兼容 |

不带界面启动：`F:\Python314\pythonw.exe run_rtguard.py --level low --control-port 8022`（工作目录 `rtguard\`）。

## 已知限制与取舍

* **只匹配双引号字面量。** YARA 的十六进制模式（`$a = { 4D 5A ?? }`）与正则模式（`$a = /re/`）不参与匹配 —— 本模块自带一个最小规则解析器，不做完整语法解析。
* **`nocase` 用双集合实现**：额外一组小写字面量 + 对 `data.lower()` 再扫一遍。不是去降低所有模式的大小写敏感度（那样会让全小写的普通规则误报）。
* **`--min-literal` 默认 6。** 规则集里有 `js`/`exe`/`ftp`/`vbs` 这类 2~5 字节短串，实测 8 MB 纯随机数据会因此误报出 `WinRAR_ADS_Traversal`、`AndroRAT_Version_Identity`。丢弃 20 个过短字面量即可消除该噪声，真样本仍正常检出。调小会增加灵敏度同时增加噪声。
* **默认只告警、不自动隔离。** 实测 `notepad.exe` 就会命中三条 LNK 相关规则，自动处置会误删系统文件。`--quarantine-on-detect` 是显式选择。
* **索引是单文件 JSON**，进程内加了锁，跨进程并发写仍是「最后写入者胜」，需要外部单实例锁。
* **托盘右键菜单未做人工点击验证**（自检只到 `start()` 返回 True）。

## 自检

```bash
# 语法与导入
python -c "import ast,os;[ast.parse(open(os.path.join(r,f),encoding='utf-8').read()) for r,d,fs in os.walk('rtguard') for f in fs if f.endswith('.py')]"
```

`.selfcheck\` 下保留了各模块开发期的自检与探针脚本，可复跑。
