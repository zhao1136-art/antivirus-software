"""把发布目录里的明文 .py 就地编译成 .pyc 并删除 .py —— 防源码泄漏。

背景
----
`御天.spec` 的 `datas=[('engine','engine')]` 会把整个 `engine/` 目录**原样**拷进
`_internal/`，于是 85 个自有源码文件以**明文 .py** 躺在发布目录里，谁都能直接
打开读。这比 PYZ 里的字节码危险得多。

但那张拷贝**不能直接删**：spec 作者留了注释说明它是**兜底**——
    "PyInstaller 的静态分析对它们不可靠。虽然 datas 的 ('engine','engine')
     哪天 datas 改成显式文件列表，这几个就会**静默消失**。"
即万一某个模块没被静态分析收进 PYZ，磁盘上这份还能让 import 成功。

做法
----
就地编译成**同级 .pyc**（legacy / sourceless 布局，不是 `__pycache__/`），
再删掉 .py：
  * CPython 的 FileFinder 支持 sourceless import，兜底能力**不变**；
  * 目录里不再有可读源码。
用当前解释器编译，`.pyc` magic 与运行时一致。

用法
----
    python strip_py_sources.py <发布目录>          # 就地处理
    python strip_py_sources.py <发布目录> --dry-run
"""
import os
import sys
import py_compile

SKIP_DIRS = {'__pycache__'}


def find_py(root):
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            if f.endswith('.py'):
                out.append(os.path.join(dp, f))
    return sorted(out)


def strip(root, dry_run=False):
    files = find_py(root)
    converted, failed = [], []
    for src in files:
        dst = src + 'c'                      # a/b.py -> a/b.pyc（legacy 布局）
        if dry_run:
            converted.append(src)
            continue
        try:
            py_compile.compile(src, cfile=dst, doraise=True, optimize=-1)
        except Exception as e:
            failed.append((src, f'{type(e).__name__}: {e}'))
            continue
        try:
            os.remove(src)
        except Exception as e:
            failed.append((src, f'删除失败: {e}'))
            continue
        converted.append(src)
    return files, converted, failed


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    root = sys.argv[1]
    dry = '--dry-run' in sys.argv
    if not os.path.isdir(root):
        print(f'不是目录: {root}')
        return 2
    files, converted, failed = strip(root, dry)
    print(f'发布目录: {root}')
    print(f'发现明文 .py: {len(files)} 个')
    print(f'{"将转换" if dry else "已转换"}: {len(converted)} 个')
    if failed:
        print(f'!! 失败 {len(failed)} 个（这些仍以明文 .py 留在包里）:')
        for f, why in failed:
            print(f'   {f}  {why}')
    remain = find_py(root)
    print(f'处理后残留明文 .py: {len(remain)} 个')
    return 0 if not failed and not remain else 1


if __name__ == '__main__':
    sys.exit(main())
