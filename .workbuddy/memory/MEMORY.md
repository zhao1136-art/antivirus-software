# 安盾项目长期记忆

## 项目概要
- **项目名称**: 安盾 - 自研杀毒软件
- **路径**: f:\杀毒
- **技术栈**: FastAPI + Uvicorn (后端), HTML5/CSS3/JS (前端), pywebview (GUI), PyInstaller (打包)
- **端口**: 8899 (主API), 9020 (P2P内网穿透), 7331 (Vigil)

## 架构
- `backend/app.py` - FastAPI 入口，所有 API 路由
- `backend/config.py` - 配置项（路径、扫描参数等）
- `backend/engine/` - 核心引擎模块
- `backend/frontend/` - HTML 前端页面

## 新增模块 (2026-07-27)

1. **system_guard.py** - 系统进程保护
   - 进程枚举 (Win32 API CreateToolhelp32Snapshot)
   - 受保护进程列表 (12个系统关键进程)
   - 进程名伪装检测 (svch0st.exe 等)
   - 可疑路径启动检测
   - 进程路径篡改检测
   - API: /api/v1/system-guard/*

2. **file_guard.py** - 系统文件防篡改
   - SHA256 哈希基线
   - 默认保护 35+ 系统文件 (kernel32.dll, ntdll.dll, hosts 等)
   - 受保护目录监控
   - 文件篡改/删除/新增检测
   - API: /api/v1/file-guard/*

3. **watchdog.py** - 后台防掉线守护
   - 每30秒自检端口8899
   - CPU/内存资源监控
   - 设置页面可关闭
   - API: /api/v1/watchdog/status, /api/v1/watchdog/toggle

## 引擎优化 (2026-07-27)

4. **ML 引擎集成到主扫描管线**
   - local_scanner.py `_scan_single_file` 第5步自动调用 ML 检测 PE 文件
   - MALICIOUS → quarantine, SUSPICIOUS → prompt

5. **Bug 修复**
   - scheduler.py: `_cloud_verify_scan` files_scanned 类型错误（int vs list）已修复
   - ml_scanner.py: 32位 PE 导入解析 thunk_size 硬编码8字节 → 动态判断32/64位

6. **YARA 增强**
   - 读取量 2MB → 16MB
   - `_search_with_mask` Sunday 算法优化

## 注意事项
- Windows 专用，大量使用 ctypes 调用 Win32 API
- 进程保护模块使用 CreateToolhelp32Snapshot 枚举进程
- 开发模式：cd backend && python app.py
- 防掉线守护默认开启，可在设置页面关闭
- fkie-cad 社区镜像现用 .json.xz 格式（lzma），31个年份文件
- CNNVD 公开 URL 返回 HTML（需登录），已改为 NVD 回退方案
- 修改前端文件后需同步到 dist/安盾/_internal/frontend/
- 修改 engine/*.py 后需同步到 dist/安盾/_internal/engine/
