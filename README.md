# 安盾杀毒软件 (Andun Antivirus)

自研多引擎杀毒软件，基于 FastAPI + Web 前端 + 原生 C++ 引擎。

## 功能特性

- **多引擎扫描**：本地特征库 / YARA 规则 / 机器学习(ML) / 云端威胁情报
- **实时防护**：文件实时监控、USB 扫描、系统进程保护、文件防篡改
- **系统安全**：应急查杀、游戏模式、开机自启动、防掉线守护
- **Web 控制台**：扫描、隔离区、防护中心、日志、漏洞、设置
- **P2P 内网穿透**：多机协作扫描（端口 9020）

## 技术栈

- 后端：Python + FastAPI + Uvicorn（端口 8899）
- 前端：HTML5 / CSS3 / JavaScript
- 原生引擎：C++ (PE 解析、启发式检测、SHA256 加速)
- GUI：pywebview，打包：PyInstaller

## 目录结构

```
backend/
├── app.py               # FastAPI 入口
├── config.py            # 配置
├── engine/              # 核心引擎
│   ├── local_scanner.py # 本地扫描
│   ├── yara_scanner.py  # YARA 规则引擎
│   ├── ml_scanner.py    # ML 检测
│   ├── cloud_scanner.py # 云端扫描
│   ├── realtime_guard.py# 实时防护
│   ├── system_guard.py  # 进程保护
│   ├── file_guard.py    # 文件防篡改
│   ├── quarantine.py    # 隔离区
│   ├── watchdog.py      # 防掉线守护
│   └── native/          # C++ 原生引擎源码
├── frontend/            # Web 前端页面
└── requirements.txt     # Python 依赖
```

## 开发运行

```bash
cd backend
pip install -r requirements.txt
python app.py
```

## 集成开源项目

| 项目 | 用途 | 说明 |
|------|------|------|
| [ClamAV](https://www.clamav.net/) | 病毒特征库/扫描 | 引擎运行时依赖，未包含二进制 |
| [YARA](https://virustotal.github.io/yara/) | 规则匹配引擎 | `engine/yara_rules/` 为规则集 |
| [capa](https://github.com/mandiant/capa) | 恶意行为分析 | 规则文件，未包含工具本体 |
| [EMBER](https://github.com/elastic/ember) | ML 特征工程 | 参考其特征提取思路 |
| [maltrail](https://github.com/stamparm/maltrail) | 威胁情报源 | 集成其情报数据 |
| [pe-sieve](https://github.com/hasherezade/pe-sieve) | 进程内存扫描 | 参考实现 |
| [yarGen](https://github.com/Neo23x0/yarGen) | 规则生成 | 辅助工具 |

> 注：第三方二进制 DLL、病毒样本库、ClamAV 引擎包等大文件未包含在本仓库，请自行下载。

## 平台

Windows 专用（大量使用 Win32 API）。

## License

本项目为自研学习项目，集成组件的版权归各自作者所有。
