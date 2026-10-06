# 待办问题清单

记录时间：2026-10-02
来源：内核驱动防护层移除（提交 `adf8581`）及之前几轮代码审计

**严重度**：🔴 崩溃或功能失效 · 🟡 质量/维护性问题 · ⚖️ 法律或发布风险 · 🟢 已修复

**统计口径**：行数含空行。自有代码 = `backend`（不含 `libs`）+ `installer`，共 144 个 Python 文件
46,571 行；原生 C/C++ 20 文件 7,667 行（删驱动后）。

---

## 一、内核驱动移除的遗留项

### 1.1 🟡 四个守护模块残留驱动空桩 —— 待拍板

文件：`privacy_shield.py`、`camera_guard.py`、`honeypot_manager.py`、`browser_guard.py`

驱动专用私有方法被保留成了同名空实现，已无实际作用：

| 方法 | 现状 |
|---|---|
| `_push_dir_protection_rule` / `_push_sensitive_file_rule`（privacy_shield） | `return 0` |
| `_push_camera_protection_rule`（camera_guard） | `return 0` |
| `_push_protect_rule` / `_remove_protect_rule`（honeypot_manager） | `return 0` / `False` |
| `_push_browser_protection_rules`（browser_guard） | `return 0` |
| `_remove_all_driver_rules` × 4 | 只清空本地 list |
| `_register_driver_handlers` / `_unregister_driver_handlers` | 空实现 |

保留的原因：让 `enable()` / `disable()` 的调用点与返回 dict 语义不变，改动风险最低。
**要彻底清除**：需连调用点一起删，并同步 `rules_pushed` / `driver_rules_count` 等返回字段。

### 1.2 🟡 `rollback_expired_rules` 恒返回成功 —— 待拍板

文件：`response_center.py`
原函数只有驱动分支（`self._kb.del_rule(rid)`），无用户态兜底。移除驱动后改为 `ok = True`。
判断依据：过期规则只存在于内存表 `self._temp_rules` 且上面已 `del`，视为回滚完成。
**若认为无驱动时应记失败**：改成 `ok = False`。

### 1.3 🟡 死代码

- `_on_file_event`（`privacy_shield.py`、`camera_guard.py`）：含用户态访问日志逻辑，但处理器不再注册，已无调用方
- `_driver_rule_ids` / `_rule_ids_lock`：只被 `get_status()` 的 `driver_rules_count`（恒 0）读取
- `from typing import Optional, Any` 里的 `Any`：在 privacy_shield / honeypot_manager / browser_guard 已无引用
- ⚠️ **不要删** `honeypot_manager` 的 `_next_rule_id` —— 它参与 baseline JSON 持久化，删了会破坏既有数据格式

### 1.4 🟡 能力净损失

防火墙（`firewall.py`）与 HIPS（`hips.py`）模块已整体删除。这两个模块原本**没有用户态实现**，
删掉驱动后即失去执行者。若另一套软件防护不接管，属产品能力净损失。

### 1.5 🟡 打包配置不在版本控制里

`御天.spec` / `御天_onedir.spec` / `installer.spec` / `uninstaller.spec` 全部被 `.gitignore`
第 11 行的 `*.spec` 排除。磁盘上已改对（删掉 `('driver','driver')` datas 与 3 个 hiddenimports），
但提交不包含它们。磁盘损坏即丢失打包配置。

### 1.6 有意保留、非缺陷

`installer\cleanup.bat` 保留旧版驱动卸载清理（`AndunDriver` 服务、Minifilter 实例、`andun.sys` 残留），
供已安装旧版驱动的用户升级时清理。删除它会让这些机器留下卸载不掉的内核服务。

---

## 二、改动前就存在的缺陷

### 2.1 🔴 反 Rootkit 会杀死 Python 进程

文件：`backend\engine\anti_rootkit.py` → `_enum_processes_ntquery`
- 现象：`SYSTEM_PROCESS_INFORMATION` 结构布局错误 → 访问违例（`0xC0000005`），
  **`try/except` 抓不到，直接杀死解释器**
- 影响：`AntiRootkit.scan()` / `scan_hidden_processes()` 一调必崩。
  删驱动前仅在降级路径上走，**现在是唯一路径**
- 已确认本次改动的 diff 未触碰该函数

### 2.2 🔴 `scan_hidden_drivers()` 恒返回 0

同文件 `_enum_drivers_usermode`：`OverflowError: int too long to convert`
（psapi 未设 `argtypes`），异常被吞 → 不崩，但隐藏驱动检测完全失效

### 2.3 🟡 `custom_rules.get_status()` 全新安装时 500

文件：`backend\engine\custom_rules.py`
- `len(self._rules)` 之前未调 `_ensure_rules()`；`custom_rules.json` 不存在时 `self._rules` 为 `None`
- 报错：`TypeError: object of type 'NoneType' has no len()`
- 已与 HEAD 对比：代码一字不差，属既有问题
- 触发条件：全新安装、尚未生成规则文件时调用该接口

### 2.4 🟢 已修复

`anti_rootkit.py` 原有 24 处 `ct.*`，但文件从未定义 `ct` 别名 —— 即改动前
`import engine.anti_rootkit` 就抛 `NameError`。已改为 `ctypes.*`（提交 `adf8581`）。

---

## 三、更早审计发现、尚未处理

### 3.1 🟢 硬编码密钥（源码已修复；git 历史仍含明文）

文件：`backend\config.py`（原第 244 行）

```python
# 修复前（密钥已脱敏，不再保留明文）
AVIC_API_KEY = "AVIC-****REDACTED****"
```

**已修复（2026-10-03）**：不再内置明文，改为

```python
# 优先级：data/config_save.json 的 cloud.avic_api_key > 环境变量 AVIC_API_KEY > 空串
AVIC_API_KEY = os.environ.get("AVIC_API_KEY", "")
```

- 沿用项目既有持久化机制（`persistence.py` 的 `config_save.json` → `cloud.avic_api_key`）作为首选来源，
  环境变量作为兜底；两者都没有时为空串，AVIC 引擎降级为「未配置」，其余引擎（微步/OTX）不受影响
- 同一明文还硬编码在 `backend\engine\cloud_scanner.py` 的 `DEFAULT_AVIC_KEY`：
  只改 `config.py` 会漏掉这条通路（它会覆盖空值），已一并改为读环境变量
- 紧邻上一行是正确写法：`CLOUD_API_KEY = os.environ.get("THREATBOOK_API_KEY", "")`

⚠️ **尚未解决**：该 key 已随提交 `a37551c` 进入 git 历史，**改文件重提交无效**。
推送 Gitee 之前必须**作废并重签这个 key**（或清理历史）。本 key 应视为已泄露。

其它明文凭据见 3.9（`test_sign.bat` 的 `CERT_PWD`），本次未改。

### 3.2 🟢 明文 HTTP 云查杀（随 AndunAI 引擎移除而消除）

原文件：`backend\config.py` → `ANDUN_BASE_URL = "http://shadu.zh.kg"`

自建云查杀引擎（AndunAI）已整体移除：`ANDUN_BASE_URL` / `ANDUN_API_KEY`、
`CloudScanner` 内的 andun 通路、`/api/v1/cloud/andun/*` 路由与前端配置项一并删除。
剩余三个引擎（AVIC / 微步在线 / AlienVault OTX）均使用 HTTPS。

### 3.3 🟡 单体架构

`backend\app.py` 约 4,400 行、**307 个 HTTP 路由、0 个 `APIRouter`**。改一处要读全文，也无法分模块测试。

### 3.4 🟡 异常处理过宽

自有代码（144 个文件、4.7 万行）中有 **646 处 `except Exception`** 与 **4 处裸 `except:`**，
平均每 70 行一次。安全软件里静默吞异常 = 界面显示"安全"。建议至少让扫描链路的异常进日志与扫描报告。

### 3.5 🟡 依赖不可复现

- `backend\requirements.txt` 只有 6 项：fastapi / uvicorn[standard] / python-multipart /
  aiofiles / requests / pyinstaller
- 实际第三方 import 有 39 个，多数靠 `backend\libs` 内置（**4,704 文件 / 2,239,743 行**）提供，
  且该目录已被 gitignore
- 后果：内置副本永远拿不到上游安全补丁 —— 安全产品跑着旧版第三方代码
- 另有 `shell=True` 1 处、`eval(` 2 处、`exec(` 2 处，建议逐一审

### 3.6 🟡 几乎没有测试

`backend\tests\` **6 个文件、569 行**，对应 4.7 万行自有代码。
建议优先覆盖"检测 → 处置"主链路：`local_scanner` / `signature_manager` / `quarantine` / `response_center`。

### 3.7 🟡 原生文件监控从未启用

文件：`backend\engine\file_guard_client.py`
`file_guard.exe` 默认禁用，需显式设 `YUTIAN_NATIVE_GUARD=1` 才拉起。原注释：

> 在加载/运行阶段存在致命 0xC0000005 访问违规风险，会拖垮主进程

实时文件保护实际由 Python 的 `realtime_guard.py` 承担。修掉这个崩溃即可解锁一个原生层能力。

### 3.8 🟡 打包环境

- 目标解释器 `F:\Python314\python.exe`（Python 3.14.4，PyInstaller 6.21.0）；
  `backend\libs` 里 251 个 `.pyd` 是 **cp314**，必须用 3.14，换版本即废
- `御天_onedir.spec` 硬编码 `F:\Python314\Lib\site-packages`
- 缺 11 个模块：`capa`、`wmi`、`win32con` / `win32event` / `win32file` / `pywintypes`、
  `msgspec`、`rich`、`lxml`、`elftools`、`flask`（后 5 个多为 capa 的传递依赖）
- `upx=True` 但 UPX 未安装（只警告，不影响出包）
- `御天_onedir.spec` 打包 `H:\Caelire\bingduku`（该空目录已在清理中删除，**打包前需重建**）；
  `御天.spec` 用的是 `f:\Caelire\bingduku`（存在），不受影响

### 3.9 🟡 `test_sign.bat` 硬编码证书密码

`installer\test_sign.bat` → `set CERT_PWD=Andun2024!`

### 3.10 ⚖️ 许可证

- **ClamAV：GPLv2** —— 把 libclamav 打进闭源产品需处理授权
- **EMBER：仓库 AGPL-v3** —— `ember_model.py` 是独立实现、不 import ember，风险较低；
  模型文件与 ember 包的分发需确认
- capa = Apache-2.0、maltrail = MIT、**yarGen = BSD-3-Clause**（无冲突）

---

## 四、本机环境干扰（优先排查）

**已安装火绒安全软件**：`C:\Program Files\Huorong\Sysdiag\bin\hramsi.dll`（v6.0.0.0，
注册为本机唯一的 AMSI Provider）。

- 验证过程中其 `AmsiScanBuffer` 触发访问违例，**打崩了 PowerShell 进程**（`0xC0000005`）
- 它会主动拦截未签名的 exe 与内核驱动 —— 在本机测试御天/安盾会与它直接冲突，
  遇到诡异崩溃时**先排除环境因素**
- 御天自己的 `amsi_provider.dll` 当前**未注册**（全机仅一个 AMSI Provider，是火绒的）
