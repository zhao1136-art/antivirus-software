#!/usr/bin/env python3
"""
从 theZoo 提取恶意样本到 test_samples/（仅静态分析用，绝不执行）
"""
import os, sys, zipfile, shutil, hashlib

THEZOO = r"F:\杀毒\theZoo-0.60.zip"
OUT_DIR = r"F:\杀毒\test_samples"

def extract_samples():
    if os.path.isdir(OUT_DIR):
        shutil.rmtree(OUT_DIR)
    os.makedirs(OUT_DIR, exist_ok=True)

    zf = zipfile.ZipFile(THEZOO)
    names = zf.namelist()
    # 家族目录
    family_dirs = sorted({n.split('/')[2] for n in names
                          if 'malwares/Binaries/' in n and len(n.split('/')) > 3})

    extracted = 0
    failed = []
    for fam in family_dirs:
        fam_prefix = f'theZoo-0.60/malwares/Binaries/{fam}/'
        # 找压缩包和密码文件
        archives = [n for n in names if n.startswith(fam_prefix) and
                    (n.endswith('.zip') or n.endswith('.rar'))]
        pass_files = [n for n in names if n.startswith(fam_prefix) and n.endswith('.pass')]

        for arc in archives:
            # 读取密码
            password = b'infected'
            base = os.path.basename(arc).rsplit('.', 1)[0]
            for pf in pass_files:
                if base in pf:
                    try:
                        password = zf.read(pf).strip()
                    except Exception:
                        pass
                    break

            # 解压到家族目录
            fam_dir = os.path.join(OUT_DIR, fam)
            os.makedirs(fam_dir, exist_ok=True)
            try:
                data = zf.read(arc)
                inner_zip_path = os.path.join(fam_dir, os.path.basename(arc))
                with open(inner_zip_path, 'wb') as f:
                    f.write(data)

                # 解压内层（密码保护）
                try:
                    with zipfile.ZipFile(inner_zip_path) as iz:
                        iz.setpassword(password)
                        for info in iz.infolist():
                            # 只提取 PE 文件（跳过文档/配置）
                            if info.filename.lower().endswith(('.exe', '.dll', '.scr', '.bin')):
                                target = os.path.join(fam_dir, os.path.basename(info.filename))
                                with iz.open(info) as src, open(target, 'wb') as dst:
                                    dst.write(src.read())
                                extracted += 1
                    os.remove(inner_zip_path)
                except Exception as e:
                    # rar 无法用 zipfile 解压，保留原压缩包标记
                    failed.append((fam, os.path.basename(arc), str(e)))
            except Exception as e:
                failed.append((fam, os.path.basename(arc), str(e)))

    print(f"提取成功: {extracted} 个 PE 样本")
    if failed:
        print(f"未解压({len(failed)}):")
        for fam, arc, err in failed[:10]:
            print(f"  {fam}/{arc}: {err[:80]}")

    # 列出最终结果
    print("\n=== test_samples 结构 ===")
    for fam in sorted(os.listdir(OUT_DIR)):
        files = os.listdir(os.path.join(OUT_DIR, fam))
        print(f"  {fam}: {len(files)} 文件")

if __name__ == '__main__':
    extract_samples()
