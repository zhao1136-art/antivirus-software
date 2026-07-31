"""
Vectorize EMBER 2018 JSONL files into memory-mapped .dat files.

The EMBER tarball ships per-sample raw features in train_features_*.jsonl
and test_features.jsonl. This script consumes those and writes:
  X_train.dat / y_train.dat / X_test.dat / y_test.dat

These are float32 (features) and float32 (labels) memmaps — same format
the ember tooling produces.

Vectorization is CPU-bound (sklearn FeatureHasher per group, per sample),
so we shard JSONL lines across a worker pool.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import glob
from concurrent.futures import ProcessPoolExecutor, as_completed

import numpy as np
from tqdm import tqdm

# Make 'src' importable when invoked as a script
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features_ember import PEFeatureExtractor


# One extractor per worker process (initialized in pool_init).
_EXTRACTOR: PEFeatureExtractor | None = None


def _pool_init():
    global _EXTRACTOR
    _EXTRACTOR = PEFeatureExtractor(feature_version=2)


def _vectorize_chunk(lines: list[str]) -> tuple[np.ndarray, np.ndarray]:
    assert _EXTRACTOR is not None
    out_x = np.empty((len(lines), _EXTRACTOR.dim), dtype=np.float32)
    out_y = np.empty((len(lines),), dtype=np.float32)
    for i, line in enumerate(lines):
        obj = json.loads(line)
        out_x[i] = _EXTRACTOR.process_raw_features(obj)
        out_y[i] = float(obj.get("label", -1))
    return out_x, out_y


def _iter_lines(paths: list[str], max_per_file: int | None):
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if max_per_file is not None and i >= max_per_file:
                    break
                yield line


def vectorize_split(jsonl_paths: list[str], x_out: str, y_out: str,
                    extractor: PEFeatureExtractor, workers: int,
                    max_per_file: int | None, chunk_size: int = 256):
    # Count rows (capped) to allocate memmaps
    total = 0
    for p in jsonl_paths:
        # cheap line count
        n = 0
        with open(p, "rb") as f:
            for _ in f:
                n += 1
        total += min(n, max_per_file or n)
    print(f"[*] {len(jsonl_paths)} file(s), {total} rows -> {x_out}")

    X = np.memmap(x_out, dtype=np.float32, mode="w+", shape=(total, extractor.dim))
    y = np.memmap(y_out, dtype=np.float32, mode="w+", shape=(total,))

    write_pos = 0
    pbar = tqdm(total=total, unit="row")

    def _flush(chunk):
        nonlocal write_pos
        xc, yc = _vectorize_chunk(chunk) if workers <= 1 else None
        return xc, yc

    if workers <= 1:
        _pool_init()
        buf: list[str] = []
        for line in _iter_lines(jsonl_paths, max_per_file):
            buf.append(line)
            if len(buf) >= chunk_size:
                xc, yc = _vectorize_chunk(buf)
                X[write_pos:write_pos + len(buf)] = xc
                y[write_pos:write_pos + len(buf)] = yc
                write_pos += len(buf)
                pbar.update(len(buf))
                buf = []
        if buf:
            xc, yc = _vectorize_chunk(buf)
            X[write_pos:write_pos + len(buf)] = xc
            y[write_pos:write_pos + len(buf)] = yc
            write_pos += len(buf)
            pbar.update(len(buf))
    else:
        with ProcessPoolExecutor(max_workers=workers, initializer=_pool_init) as ex:
            futures = []
            buf: list[str] = []

            def _submit(chunk):
                futures.append(ex.submit(_vectorize_chunk, chunk))

            for line in _iter_lines(jsonl_paths, max_per_file):
                buf.append(line)
                if len(buf) >= chunk_size:
                    _submit(buf)
                    buf = []
            if buf:
                _submit(buf)

            # Results may complete out of order, but we want positional writes.
            # Since each future was submitted for a contiguous chunk, we
            # process them in submission order (futures list order).
            for fut in futures:
                xc, yc = fut.result()
                n = xc.shape[0]
                X[write_pos:write_pos + n] = xc
                y[write_pos:write_pos + n] = yc
                write_pos += n
                pbar.update(n)

    pbar.close()
    X.flush(); y.flush()
    print(f"    wrote {write_pos} rows")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/ember2018")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--max-per-file", type=int, default=0,
                    help="if >0, only vectorize the first N rows of each JSONL file")
    args = ap.parse_args()

    extractor = PEFeatureExtractor(feature_version=2)
    assert extractor.dim == 2381, f"expected 2381 dims, got {extractor.dim}"

    train_files = sorted(glob.glob(os.path.join(args.data_dir, "train_features_*.jsonl")))
    test_files = sorted(glob.glob(os.path.join(args.data_dir, "test_features*.jsonl")))
    if not train_files or not test_files:
        raise SystemExit(f"missing JSONL files under {args.data_dir}")

    cap = args.max_per_file or None
    print(f"[*] workers={args.workers}, max_per_file={cap}")

    vectorize_split(
        train_files,
        os.path.join(args.data_dir, "X_train.dat"),
        os.path.join(args.data_dir, "y_train.dat"),
        extractor, args.workers, cap,
    )
    vectorize_split(
        test_files,
        os.path.join(args.data_dir, "X_test.dat"),
        os.path.join(args.data_dir, "y_test.dat"),
        extractor, args.workers, cap,
    )
    print("[*] done.")


if __name__ == "__main__":
    main()
