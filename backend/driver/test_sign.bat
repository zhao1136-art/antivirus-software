@echo off
chcp 65001 >nul 2>&1
REM ============================================================
REM 御天内核驱动测试签名脚本
REM
REM 前置条件：
REM   1. 已安装 WDK
REM   2. 已运行 build.bat 编译出 andun.sys
REM   3. 系统已开启测试签名模式
REM      开启方法: bcdedit /set testsigning on (需重启)
REM
REM 用法：
REM   test_sign.bat    - 创建测试证书并签名驱动
REM ============================================================

setlocal

set DRIVER_SYS=%~dp0andun.sys
set CERT_NAME=御天测试证书
set CERT_FILE=%TEMP%\andun_test.pfx
set CERT_PWD=Andun2024!

REM --- 检查管理员权限 ---
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo [御天驱动] 错误: 需要管理员权限
    exit /b 1
)

REM --- 检查驱动文件 ---
if not exist "%DRIVER_SYS%" (
    echo [御天驱动] 错误: 未找到 andun.sys，请先运行 build.bat 编译
    exit /b 1
)

REM --- 查找工具 ---
where makecert >nul 2>&1
if !errorlevel! neq 0 (
    echo [御天驱动] 错误: 未找到 makecert.exe
    echo [御天驱动] 请确保 WDK 已安装并在 PATH 中
    exit /b 1
)

where signtool >nul 2>&1
if !errorlevel! neq 0 (
    echo [御天驱动] 错误: 未找到 signtool.exe
    echo [御天驱动] 请确保 WDK 已安装并在 PATH 中
    exit /b 1
)

REM --- 创建测试证书 ---
echo [御天驱动] 创建测试证书...
makecert -r -pe -ss PrivateCertStore -n "CN=%CERT_NAME%" -sky signature "%CERT_FILE%" -sp "Microsoft Base Cryptographic Provider v1.0" -sy 1 2>nul
if !errorlevel! neq 0 (
    echo [御天驱动] 创建证书失败，尝试使用 New-SelfSignedCertificate...
    powershell -Command "$cert = New-SelfSignedCertificate -Subject 'CN=%CERT_NAME%' -CertStoreLocation 'Cert:\LocalMachine\My' -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -Provider 'Microsoft Base Cryptographic Provider v1.0'; $pwd = ConvertTo-SecureString -String '%CERT_PWD%' -Force -AsPlainText; Export-PfxCertificate -Cert $cert -FilePath '%CERT_FILE%' -Password $pwd"
    if !errorlevel! neq 0 (
        echo [御天驱动] 创建证书失败
        exit /b 1
    )
)

REM --- 签名驱动 ---
echo [御天驱动] 签名驱动...
signtool sign /f "%CERT_FILE%" /p "%CERT_PWD%" /v /t http://timestamp.digicert.com "%DRIVER_SYS%"
if !errorlevel! neq 0 (
    echo [御天驱动] 签名失败
    echo [御天驱动] 尝试不带时间戳签名...
    signtool sign /f "%CERT_FILE%" /p "%CERT_PWD%" /v "%DRIVER_SYS%"
    if !errorlevel! neq 0 (
        echo [御天驱动] 签名仍然失败
        exit /b 1
    )
)

echo [御天驱动] 签名成功
echo [御天驱动]
echo [御天驱动] 下一步:
echo [御天驱动] 1. 确保已开启测试签名: bcdedit /set testsigning on (需重启)
echo [御天驱动] 2. 运行安装脚本: install_driver.bat install

REM --- 清理 ---
del "%CERT_FILE%" 2>nul

endlocal
