# -*- coding: utf-8 -*-
"""御天安全卫士 · 安装/删除程序 一键构建脚本
流程：
  1. 校验已打包的 御天 程序（backend\\dist\\御天\\御天.exe）
  2. 将 御天 程序压缩为 御天.zip（供安装程序解压）
  3. 构建 删除程序.exe（PyInstaller onefile）
  4. 构建 御天安装程序.exe（PyInstaller onefile，内嵌 删除程序.exe）
产物：installer\\dist\\{ 御天安装程序.exe, 删除程序.exe, 御天.zip }
"""
import os
import sys
import shutil
import subprocess
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist")
BUILD = os.path.join(ROOT, "build")
YT_DIST = os.path.join(ROOT, "..", "backend", "dist", "御天")
YT_ZIP = os.path.join(ROOT, "御天.zip")
PY = r"F:\Python314\python.exe"
ICON = os.path.join(ROOT, "..", "backend", "御天图标.ico")


def run(cmd, cwd=None):
    print("\n>>", " ".join('"{0}"'.format(c) if " " in c else c for c in cmd))
    subprocess.check_call(cmd, cwd=cwd)


def make_zip(force=False):
    """将 backend\\dist\\御天 压缩为 御天.zip"""
    main_exe = os.path.join(YT_DIST, "御天.exe")
    if not os.path.isfile(main_exe):
        print("[错误] 未找到 %s\n请先运行 backend\\打包御天.cmd 完成主程序打包。" % main_exe)
        return False
    # 已存在则跳过（如需重新压缩，删除御天.zip 或用 --force）
    if os.path.exists(YT_ZIP) and not force:
        print("[1/3] 御天.zip 已存在，跳过压缩（约 {0:.1f} MB）".format(
            os.path.getsize(YT_ZIP) / 1048576))
        return True
    if os.path.exists(YT_ZIP):
        os.remove(YT_ZIP)
    count = 0
    with zipfile.ZipFile(YT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, _dirs, files in os.walk(YT_DIST):
            for name in files:
                full = os.path.join(root, name)
                arc = os.path.relpath(full, YT_DIST)
                zf.write(full, arc)
                count += 1
    size = os.path.getsize(YT_ZIP) / 1048576
    print("[1/3] 御天.zip 已生成：{0} 个文件，约 {1:.1f} MB".format(count, size))
    return True


def build_uninstaller():
    """构建 删除程序.exe"""
    out = os.path.join(DIST, "删除程序.exe")
    run([PY, "-m", "PyInstaller", "--noconfirm", "--clean",
         "--distpath", DIST, "--workpath", os.path.join(BUILD, "uninstaller"),
         os.path.join(ROOT, "uninstaller.spec")], cwd=ROOT)
    if not os.path.isfile(out):
        raise SystemExit("[错误] 删除程序.exe 构建失败")
    print("[2/3] 删除程序.exe 已生成")
    return out


def build_installer():
    """构建 御天安装程序.exe"""
    out = os.path.join(DIST, "御天安装程序.exe")
    run([PY, "-m", "PyInstaller", "--noconfirm", "--clean",
         "--distpath", DIST, "--workpath", os.path.join(BUILD, "installer"),
         os.path.join(ROOT, "installer.spec")], cwd=ROOT)
    if not os.path.isfile(out):
        raise SystemExit("[错误] 御天安装程序.exe 构建失败")
    print("[3/3] 御天安装程序.exe 已生成")
    return out


def main():
    if not os.path.isfile(PY):
        print("[错误] 未找到 Python：%s" % PY)
        return 1
    os.makedirs(DIST, exist_ok=True)
    os.makedirs(BUILD, exist_ok=True)
    if not make_zip():
        return 1
    build_uninstaller()
    build_installer()
    print("\n✅ 构建完成！发布文件位于：")
    print("   %s" % os.path.join(DIST, "御天安装程序.exe"))
    print("   %s" % YT_ZIP)
    print("   %s" % os.path.join(DIST, "删除程序.exe"))
    print("\n分发时请将 御天安装程序.exe 与 御天.zip 放在同一目录。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
