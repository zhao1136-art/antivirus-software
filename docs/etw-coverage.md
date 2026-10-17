# ETW 实时防护 · 覆盖地图

> 本文由 `tools/gen_etw_coverage.py` 从原生层源码生成，数据（规则归属、事件 ID、限流值）全部来自代码，不是手抄。
> 改完 `etw_rules.cpp` / `etw_guard.cpp` 后重跑本脚本即可同步。

## 一、能看见什么

| Provider | 语义上能看见 | 事件 ID | 规则数 |
|---|---|---|---|
| **Threat-Intelligence** | 进程内存读 / 远程线程 / APC 注入 / 句柄篡改 | `1, 12, 17` | 9 |
| **Kernel-Process** | 进程与线程的创建/终止（含父 PID、命令行） | `1, 2, 3, 4, 5, 6, 7, 8` | 6 |
| **DNS-Client** | DNS 查询与响应（域名） | `3006, 3008` | 2 |
| **PowerShell** | 脚本块日志（4104）/ 执行（4103）/ 引擎（800） | `4104, 4103, 800` | 1 |
| **WMI-Activity** | 持久化三件套：消费者 / 过滤器 / 绑定（11/22/23） | `11, 22, 23` | 1 |
| **DotNETRuntime** | .NET 运行时事件（全量保留） | `全量` | 1 |
| **Sysmon** | 进程创建 / 网络 / 镜像加载 / 文件创建（1/3/7/11） | `1, 3, 7, 11` | 4 |
| **Kernel-File** | 文件创建/重命名（不含写入内容、不含删除） | `12, 30, 31` | 3 |
| **Kernel-Registry** | 注册表创建/打开/设值/删除 | `1, 2, 5, 22` | 2 |

合计 **29** 条 ETW 规则。

## 二、规则明细（按 Provider）

### Threat-Intelligence（9 条）

```
TI_MAP_VIEW_SECTION             TI_PROCESS_INJECTION            TI_PROCESS_TAMPERING            TI_QUEUE_APC
TI_READ_PROC_MEMORY             TI_REMOTE_THREAD                TI_SET_THREAD_CONTEXT           TI_UNKNOWN_ATTACK
TI_WRITE_PROC_MEMORY
```

### Kernel-Process（6 条）

```
DLL_SIDELOAD                    ENCODED_CMDLINE                 OFFICE_SPAWNS_SCRIPT            SCRIPT_CHAIN
SUSPICIOUS_EXEC_LOCATION        SVC_HOST_SPAWNS_SCRIPT
```

### DNS-Client（2 条）

```
DGA_DOMAIN                      DNS_NXDOMAIN_BEACON
```

### PowerShell（1 条）

```
PS_OBFUSCATED_SCRIPT
```

### WMI-Activity（1 条）

```
WMI_PERSISTENCE
```

### DotNETRuntime（1 条）

```
DOTNET_SUSPICIOUS_ASSEMBLY
```

### Sysmon（4 条）

```
DGA_DOMAIN_SYSMON               DLL_SIDELOAD_SYSMON             LSASS_CREDENTIAL_ACCESS         NAMED_PIPE_C2
```

### Kernel-File（3 条）

```
FILE_DROP_EXEC                  SHADOWCOPY_ACCESS               STARTUP_FOLDER_WRITE
```

### Kernel-Registry（2 条）

```
DEFENDER_DISABLE_TAMPER         REG_PERSISTENCE_WRITE
```

## 三、会在什么条件下漏掉（重点）

这一节是这份文档存在的理由 —— 上面写的是能力，这里写的是**边界**。

### 1. 限流：超过就丢，不重试

| Provider | 上限 |
|---|---|
| Kernel-File | **120 事件/秒** |
| Kernel-Process | **150 事件/秒** |
| DNS-Client | **200 事件/秒** |
| 其余 6 个 | **100 事件/秒** |

**后果**：解压一个含上千文件的压缩包、批量编译、批量下载 —— 文件事件瞬间打到几百上千/秒，**超过 120/s 的部分全丢**，丢弃计数累加到 `g_totalDropped`。

### 2. 命中队列只有 512 个槽位

环形缓冲满了走背压丢弃，计数累加到 `g_totalBackpressure`。**攻击者可以用大量无关事件把队列挤爆**，让自己的恶意事件被背压丢掉。

### 3. 限流是无差别的 —— 真实命中也会被丢

`handle_user_event()` 里的顺序是：先跑分析器得出 `hit`，**再**过滤、**再**限流：

```cpp
switch (prov) { case PROV_SYSMON: hit = analyze_sysmon(...); ... }  // 先判定
bool highValue = (!hit && etw_is_high_value_event(prov, ev.eventId));
if (!hit && !highValue) return;
if (!etw_rate_check(prov)) return;   // ← 命中事件同样过这道闸
```

**后果**：某个 provider 一旦打到限流上限，**连已经判定为命中的事件也会被丢掉**，而且不重试、不落盘。也就是说「事件洪峰」不只是延迟，而是**直接丢检测结果**。

这是当前最容易出事的一处：攻击者只要在同 provider 上制造足够多的无关事件（比如大量文件创建、进程创建），就能把自己的恶意事件挤到限流之外。

### 4. 事件 ID 白名单只影响「保留」，不影响「检测」

`HIGH_VALUE_EVENTS` 容易被误解成「只订阅这些 ID」。实际读代码：分析器是**按 provider 无条件调用**的（`switch (prov)` 不看事件 ID），白名单只决定「**没命中规则时**这条事件要不要留着做进程链分析」。

所以白名单里没列出的事件 ID，只要 provider 有发出，规则照样能被触发。**代价是**：没命中又不在白名单里的事件被直接丢弃（`return`），进程链/时间线分析因此缺料。

各 provider 的保留范围：

- **Threat-Intelligence**：只对**签名**杀软开放；未签名构建该 provider 启用会失败
- **Kernel-Process**：只看创建那一刻，看不到进程之后做了什么
- **DNS-Client**：看不到非 DNS 的 C2（直连 IP、DoH）
- **PowerShell**：只在 PowerShell 引擎启用脚本块日志时才有内容
- **WMI-Activity**：**不含 T1047（WMI 创建进程）** —— 那是进程链侧的事
- **DotNETRuntime**：只覆盖托管程序
- **Sysmon**：**依赖用户自装 Sysmon**，没装则整个 provider 空转
- **Kernel-File**：**只订阅了 12/30/31 三个 ID**，写入与删除事件没订阅
- **Kernel-Registry**：只订阅 1/2/5/22，其余键操作看不到

### 5. TI 层在未签名构建上是空的

`Microsoft-Windows-Threat-Intelligence` **只对持有杀毒签名的产品开放**。未签名 / 自签名的构建里该 provider 启用失败，`analyze_ti` 的规则（进程注入、远程线程、APC、内存读写）**一条都不会触发**。

好在这是**可观测**的：状态输出里每个 provider 都有 `enable_ok` 字段
（`etw_guard.cpp` 的 provider 状态 JSON）。**上线前必须查这个字段**，不能假设 TI 层在工作。

### 6. 需要管理员权限

`StartTraceW` + 内核 provider 都需要管理员。非管理员运行时 ETW 整体不可用，只剩用户态的文件系统监控。

### 7. Sysmon 是外部依赖

`Sysmon` provider 只有在用户自己装了 Sysmon 之后才有事件。它带来的 `DGA_DOMAIN_SYSMON` / `DLL_SIDELOAD_SYSMON` 在裸机上永远不会触发。

## 四、怎么自查当前机器的实际覆盖

看 ETW 状态接口，重点四个字段：

```
providers[].enable_ok      # 每个 provider 是否真的启用成功（TI 重点看这个）
providers[].captured      # 实际捕获量
providers[].suspicious    # 命中量
dropped / backpressure_drops  # 丢了多少（这两个不为 0 说明在漏）
```

**判读**：`dropped` 持续增长 = 该机器的事件量超出了限流，要么调上限要么接受漏；`enable_ok=false` 的 provider 那一层等于不存在。

## 五、明确未覆盖的攻击面

以下这些**当前架构看不见**，需要单独说明或另想办法：

- **WMI 创建进程（T1047 / `Win32_Process.Create`）**：WMI provider 只看持久化三件套（11/22/23），进程创建侧要指望 `Kernel-Process` 能看到父进程是 `WmiPrvSE.exe` —— 但那需要分析进程链，`analyze_kproc` 里没有这条规则。
- **写入内容**：`Kernel-File` 只有创建/重命名，**看不到写进去什么**。落地即加密的勒索行为只能靠事后扫描。
- **删除与覆盖**：没订阅删除类事件，`DeleteFile` 行为不可见。
- **非 DNS 的 C2**：直连 IP、DoH/DoT、域前置都绕开 `DNS-Client`。
- **无文件执行的内存载荷**：没有内存扫描触发点（要 TI 层或定期扫）。
- **驱动层**：全部是用户态 ETW，没有 minifilter / 内核回调，绕过 ETW 的手法（如直接系统调用）完全看不到。

---

> 这份地图的作用不是证明覆盖得广，而是让「哪里会漏」变成已知事实，而不是等出事之后再猜。