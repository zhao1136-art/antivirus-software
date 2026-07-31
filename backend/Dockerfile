# 安盾后端 - Linux 容器化部署
# 说明：进程保护(system_guard)、文件防篡改(file_guard)、实时守护(client)
#       依赖 Windows API，在 Linux 容器中自动降级（代码已用 sys.platform 守卫）。
#       跨平台核心查杀（YARA / 签名 / ML特征 / 漏洞库）完整可用。
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# 安装运行所需依赖（注意：不安装 pyinstaller，那是 Windows 打包用的）
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        fastapi \
        "uvicorn[standard]" \
        python-multipart \
        aiofiles \
        requests \
        numpy \
        pefile

# 拷贝业务代码（libs/ dist/ 等由 .dockerignore 排除，避免把 Windows 第三方库打进镜像）
COPY . .

# API 端口
EXPOSE 8899

# 启动 FastAPI
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port 8899"]
