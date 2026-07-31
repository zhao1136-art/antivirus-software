"""
Auto-updater for model weights.

Fetches a manifest (JSON) listing each model file, an expected SHA256,
a download URL, and a version stamp. For each entry, if the local file's
SHA256 doesn't match the manifest, download the remote, verify SHA256
again, then atomic-replace (move the old file to archive/ first).

Pass --manifest <path|url> to override the default URL. A local path is
fine for testing or for an air-gapped install.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(HERE, "models")
ARCHIVE_DIR = os.path.join(MODELS_DIR, "archive")

# TODO: replace with your GitHub releases URL before publishing models
DEFAULT_MANIFEST_URL = ""


# ---------- helpers ---------------------------------------------------------

def _sha256_of(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _is_url(s: str) -> bool:
    p = urlparse(s)
    return p.scheme in ("http", "https")


def _load_manifest(src: str) -> dict[str, Any]:
    if _is_url(src):
        print(f"[update] fetching manifest: {src}")
        r = requests.get(src, timeout=30)
        r.raise_for_status()
        return r.json()
    print(f"[update] reading manifest: {src}")
    with open(src, "r", encoding="utf-8") as f:
        return json.load(f)


def _download(src: str, dest: str, expected_sha: str) -> None:
    """Stream `src` (URL or local file path) into `dest`, verify SHA256."""
    if _is_url(src):
        print(f"[update]   GET {src}")
        with requests.get(src, stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=1 << 16):
                    if chunk:
                        f.write(chunk)
    else:
        print(f"[update]   copy {src}")
        shutil.copy2(src, dest)
    got = _sha256_of(dest)
    if got != expected_sha:
        os.remove(dest)
        raise RuntimeError(
            f"sha256 mismatch for {os.path.basename(dest)}: "
            f"expected {expected_sha[:12]}..., got {got[:12]}..."
        )


def _archive_local(model_path: str) -> str:
    """Move-rename old file into archive/ as <stem>_pre-update_<ts>.lgbm."""
    if not os.path.isfile(model_path):
        return ""
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    stem, ext = os.path.splitext(os.path.basename(model_path))
    dest = os.path.join(ARCHIVE_DIR, f"{stem}_pre-update_{ts}{ext}")
    shutil.copy2(model_path, dest)
    return dest


# ---------- main update -----------------------------------------------------

def update_models(manifest_src: str, dry_run: bool = False) -> dict[str, Any]:
    """Apply every entry in the manifest. Returns a per-model report dict."""
    manifest = _load_manifest(manifest_src)
    entries = manifest.get("models", [])
    report: dict[str, Any] = {
        "manifest_version": manifest.get("version"),
        "manifest_timestamp": manifest.get("timestamp"),
        "checked": 0,
        "updated": [],
        "up_to_date": [],
        "failed": [],
    }

    for entry in entries:
        name = entry["name"]
        local_rel = entry.get("local_path", os.path.join("models", name))
        local_path = os.path.join(HERE, local_rel)
        remote = entry["url"]
        expected_sha = entry["sha256"].lower()
        version = entry.get("version")
        report["checked"] += 1

        local_sha = _sha256_of(local_path) if os.path.isfile(local_path) else None
        same = local_sha == expected_sha
        print(f"[update] {name}  manifest_ver={version}  remote_sha={expected_sha[:12]}...  "
              f"local_sha={(local_sha or 'absent')[:12]}{'...' if local_sha else ''}  "
              f"{'(match)' if same else '(differs)'}")

        if same:
            report["up_to_date"].append(name)
            continue

        if dry_run:
            print(f"[update]   DRY RUN: would update {local_rel}")
            report["updated"].append({"name": name, "dry_run": True})
            continue

        archived = _archive_local(local_path)
        # Download to a temp file in the same directory (so the rename is atomic).
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "wb", delete=False, dir=os.path.dirname(local_path), prefix=".tmp_", suffix=".dl",
        ) as tmp:
            tmp_path = tmp.name
        try:
            _download(remote, tmp_path, expected_sha)
            # On Windows, os.replace handles the cross-rename atomically.
            os.replace(tmp_path, local_path)
        except Exception as e:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            report["failed"].append({"name": name, "error": str(e)})
            print(f"[update]   FAILED: {e}")
            continue

        print(f"[update]   updated -> {local_path}")
        if archived:
            print(f"[update]   prior version archived -> {archived}")
        report["updated"].append({
            "name": name,
            "archived": archived,
            "version": version,
            "sha256": expected_sha,
        })

    return report


# ---------- CLI -------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Check / apply model updates from a manifest.")
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST_URL,
                    help="manifest URL or local path (no default until DEFAULT_MANIFEST_URL is set)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report differences but don't download or replace anything")
    args = ap.parse_args()
    if not args.manifest:
        ap.error("no manifest source; pass --manifest <url|path> "
                 "(DEFAULT_MANIFEST_URL is unset in this build)")

    t0 = time.time()
    try:
        report = update_models(args.manifest, dry_run=args.dry_run)
    except Exception as e:
        print(f"[update] ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    elapsed = time.time() - t0

    print()
    print("=" * 56)
    print(f"  checked     : {report['checked']}")
    print(f"  up to date  : {len(report['up_to_date'])}  {report['up_to_date']}")
    print(f"  updated     : {len(report['updated'])}    {[u['name'] for u in report['updated']]}")
    print(f"  failed      : {len(report['failed'])}    {[f['name'] for f in report['failed']]}")
    print(f"  elapsed     : {elapsed:.2f}s")
    print("=" * 56)
    sys.exit(0 if not report["failed"] else 1)


if __name__ == "__main__":
    main()
