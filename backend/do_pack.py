import PyInstaller.__main__
import os, sys, shutil

# 清理旧的 dist_new
for d in ['dist_new', 'build']:
    if os.path.exists(d):
        shutil.rmtree(d, ignore_errors=True)

# 运行 PyInstaller
PyInstaller.__main__.run([
    '安盾.spec',
    '--clean',
    '--noconfirm',
    '--distpath', 'dist_new',
])

print("打包完成！")