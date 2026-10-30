# 内核驱动（实验性 — 不要用于生产）

> **状态：实验性 / 未完成 / 未签名 / 从未成功编译。**
> 本目录的代码**不随发布包分发**，也不参与任何默认启用路径。
> 保留它只是为了记录设计意图与后续研究，不等于产品具备内核态能力。

## 它是什么

Windows 内核驱动（WDM）的**设计草稿**，目标是把用户态做不到的几类观测下沉到内核：

| 文件 | 意图 |
|---|---|
| `driver_main.c` / `andun.h` | 驱动入口、设备对象、IOCTL 定义 |
| `process_callback.c` | 进程创建回调（PsSetCreateProcessNotifyRoutineEx） |
| `object_callback.c` | 句柄/对象访问回调 |
| `registry_callback.c` | 注册表操作回调 |
| `file_filter.c` | 文件操作过滤 |
| `network_filter.c` | 网络连接观测 |
| `rule_engine.c` | 驱动侧规则匹配 |
| `rootkit_scan.c` | 反 rootkit 扫描 |
| `self_protect.c` | 自保护（防卸载/防结束） |
| `response.c` | 内核侧处置动作 |
| `event_queue.c` | 内核 → 用户态事件队列 |
| `device_control.c` | 用户态通信通道 |
| `install_driver.bat` / `test_sign.bat` / `build.bat` | 安装、测试签名、构建脚本 |

## 为什么现在不能用

1. **没有编译过**。`.github/workflows/build-driver.yml` 记录得很清楚：
   该工作流**从未成功跑通**，第一次运行几乎必然在编译阶段报一堆错。
   目前连 `andun.sys` 都不存在。
2. **没有签名**。内核驱动必须签名才可加载：
   - 测试用途：Windows 需进入 **测试签名模式**（`bcdedit /set testsigning on`），
     且重启后桌面右下角会有水印；
   - 生产用途：需要 **EV 代码签名证书** + Microsoft 的 attestation 签名，
     有持续成本与审核周期。
3. **未签名驱动会直接蓝屏或加载失败**。在别人的机器上加载未签名驱动属于
   最高风险操作，可能造成系统无法启动。
4. **兼容性未知**。目标版本只写了 Windows 10，没有在 11 / Server 上验证过；
   WDM 的 IRP 处理、回调注册在卸载顺序上稍有差错就会 BSOD。

## 因此产品的定位是（见根 README）

- **默认全部走用户态**：YARA、ETW 行为监控、AMSI Provider、注入检测、
  持久化监控、PE/ML 检测。
- **内核驱动是实验性可选方向**，不随发布包分发，不要求用户开启，
  也不会自动加载。
- 用户态方案的已知盲区（例如直接系统调用绕过 ETW）**如实承认**，
  而不是用一个不可靠的驱动假装覆盖了。

## 如果你要在这台机器上试（自行承担风险）

```powershell
# 1) 先做系统还原点 / 用虚拟机（强烈建议）
# 2) 装 WDK + MSVC（或直接用 CI 产物）
# 3) 测试签名模式
bcdedit /set testsigning on      # 需要重启
# 4) 生成测试证书并签名后再安装；不要跳过签名
```

**在虚拟机快照里做，不要在承载数据的实体机上做。**

## 相关说明

- 构建流程：`.github/workflows/build-driver.yml`
- 第三方许可：见 `../licenses/THIRD_PARTY_LICENSES.md`
- 打包脚本 `backend/御天.spec` **不含**本目录（`datas` 只收 `engine/`、
  `frontend/`、`ui_tk/` 等），所以发布包里没有驱动。
