#!/usr/bin/env python3
"""Download N open-source APKs from the official F-Droid repository."""

from __future__ import annotations

import argparse
import io
import json
import logging
import random
import re
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


LOG = logging.getLogger("fdroid_download")
INDEX_URL = "https://f-droid.org/repo/index-v1.jar"
REPO_BASE = "https://f-droid.org/repo/"
USER_AGENT = "apkleaks-skills-fdroid-downloader/1.0 (+authorized security research)"
_APK_NAME_RE = re.compile(r"^(.+)_(\d+)\.apk$", re.IGNORECASE)


def _http_get(url: str, timeout: int = 120) -> bytes:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def load_index() -> dict:
    LOG.info("Fetching F-Droid index: %s", INDEX_URL)
    raw = _http_get(INDEX_URL, timeout=180)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        with zf.open("index-v1.json") as fh:
            return json.load(fh)


def package_from_apk_name(name: str) -> str | None:
    """Extract package id from F-Droid style `package_versionCode.apk` names."""
    m = _APK_NAME_RE.match(name.strip())
    return m.group(1) if m else None


def existing_apk_names(out_dir: Path) -> set[str]:
    if not out_dir.is_dir():
        return set()
    return {p.name for p in out_dir.glob("*.apk") if p.is_file()}


def existing_package_names(out_dir: Path) -> set[str]:
    """Packages already present on disk (any version)."""
    pkgs: set[str] = set()
    for name in existing_apk_names(out_dir):
        pkg = package_from_apk_name(name)
        if pkg:
            pkgs.add(pkg)
    return pkgs


def scanned_package_names(results_dir: Path | None) -> set[str]:
    """Packages that already have a scan result JSON (any version)."""
    if results_dir is None or not results_dir.is_dir():
        return set()
    skip = {
        "status.json",
        "summary.json",
        "dashboard-config.json",
        "download-status.json",
    }
    pkgs: set[str] = set()
    for path in results_dir.glob("*.json"):
        if path.name in skip:
            continue
        pkg = package_from_apk_name(path.name.replace(".json", ".apk"))
        if pkg:
            pkgs.add(pkg)
            continue
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        apk = job.get("apk") if isinstance(job, dict) else None
        if isinstance(apk, str):
            p2 = package_from_apk_name(apk)
            if p2:
                pkgs.add(p2)
    return pkgs


def select_packages(
    index: dict,
    count: int,
    seed: int | None = None,
    exclude_names: set[str] | None = None,
    exclude_packages: set[str] | None = None,
) -> list[dict]:
    apps = index.get("apps") or []
    packages = index.get("packages") or {}
    exclude = exclude_names or set()
    exclude_pkgs = exclude_packages or set()
    candidates = []
    for app in apps:
        pkg = app.get("packageName")
        if not pkg or pkg not in packages:
            continue
        if pkg in exclude_pkgs:
            continue
        versions = packages[pkg]
        if not versions:
            continue
        # Prefer the first listed package version (usually newest in index-v1).
        ver = versions[0]
        apk_name = ver.get("apkName")
        if not apk_name or apk_name in exclude:
            continue
        candidates.append({
            "packageName": pkg,
            "name": app.get("name") or pkg,
            "apkName": apk_name,
            "versionName": ver.get("versionName"),
            "size": ver.get("size"),
        })
    if not candidates:
        return []

    rng = random.Random(seed)
    rng.shuffle(candidates)
    return candidates[: max(1, count)] if count > 0 else []


def download_apk(meta: dict, out_dir: Path, overwrite: bool = False) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / meta["apkName"]
    if target.exists() and not overwrite:
        LOG.info("Skip existing %s", target.name)
        return target
    url = REPO_BASE + meta["apkName"]
    LOG.info("Downloading %s (%s)", meta["packageName"], meta["apkName"])
    data = _http_get(url, timeout=180)
    tmp = target.with_suffix(target.suffix + ".part")
    tmp.write_bytes(data)
    tmp.replace(target)
    return target


def run(
    count: int,
    out_dir: Path,
    seed: int | None = None,
    overwrite: bool = False,
    results_dir: Path | None = None,
    workers: int = 1,
) -> dict:
    index = load_index()
    out_dir.mkdir(parents=True, exist_ok=True)
    # Dedup by exact APK filename AND package id (any version already on disk
    # or already scanned). Prevents re-downloading the same app under a new
    # versionCode.
    exclude_names: set[str] = set()
    exclude_pkgs: set[str] = set()
    if not overwrite:
        exclude_names = existing_apk_names(out_dir)
        exclude_pkgs = existing_package_names(out_dir) | scanned_package_names(results_dir)
    selected = select_packages(
        index,
        count,
        seed=seed,
        exclude_names=exclude_names,
        exclude_packages=exclude_pkgs,
    )
    results: list[dict] = []
    skipped_existing = len(exclude_names)
    skipped_packages = len(exclude_pkgs)
    workers_n = max(1, min(32, int(workers or 1)))
    if not selected:
        LOG.warning("No new packages to download (all skipped or index empty)")
        summary = {
            "ok": True,
            "requested": count,
            "selected": 0,
            "downloaded": 0,
            "failed": 0,
            "skipped_existing": skipped_existing,
            "skipped_packages": skipped_packages,
            "workers": workers_n,
            "output_dir": str(out_dir),
            "apps": [],
        }
        (out_dir / "fdroid-manifest.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary
    LOG.info("Downloading %s APK(s) with %s parallel worker(s)", len(selected), workers_n)

    def _one(meta: dict) -> dict:
        try:
            path = download_apk(meta, out_dir, overwrite=overwrite)
            return {**meta, "ok": True, "path": str(path), "skipped_duplicate": False}
        except (HTTPError, URLError, OSError, TimeoutError) as exc:
            LOG.error("Failed %s: %s", meta["packageName"], exc)
            return {**meta, "ok": False, "error": str(exc)}

    progress = tqdm(total=len(selected), desc="Downloading APKs", unit="apk") if tqdm else None
    try:
        if workers_n == 1:
            for meta in selected:
                results.append(_one(meta))
                if progress is not None:
                    progress.update(1)
        else:
            with ThreadPoolExecutor(max_workers=workers_n) as pool:
                futures = {pool.submit(_one, meta): meta for meta in selected}
                for fut in as_completed(futures):
                    results.append(fut.result())
                    if progress is not None:
                        progress.update(1)
    finally:
        if progress is not None:
            progress.close()

    summary = {
        "ok": True,
        "requested": count,
        "selected": len(selected),
        "downloaded": sum(1 for r in results if r.get("ok")),
        "failed": sum(1 for r in results if not r.get("ok")),
        "skipped_existing": skipped_existing,
        "skipped_packages": skipped_packages,
        "workers": workers_n,
        "output_dir": str(out_dir),
        "apps": results,
    }
    (out_dir / "fdroid-manifest.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download N APKs from the official F-Droid repo (open-source apps only)",
    )
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=100,
        help="Number of APKs to download (default: 100)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="apks",
        help="Output directory (default: apks)",
    )
    parser.add_argument(
        "--results",
        default=None,
        help="Results dir — skip packages already scanned there",
    )
    parser.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible selection")
    parser.add_argument("--overwrite", action="store_true", help="Re-download even if file exists")
    parser.add_argument(
        "-j",
        "--workers",
        type=int,
        default=10,
        help="Parallel download threads (default: 10, max 32)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.count < 1:
        LOG.error("count must be >= 1")
        return 2
    if args.workers < 1 or args.workers > 32:
        LOG.error("workers must be 1..32")
        return 2

    try:
        summary = run(
            args.count,
            Path(args.output),
            seed=args.seed,
            overwrite=args.overwrite,
            results_dir=Path(args.results) if args.results else None,
            workers=args.workers,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.error("%s", exc)
        return 1

    print(json.dumps({
        "ok": summary["ok"],
        "requested": summary["requested"],
        "downloaded": summary["downloaded"],
        "failed": summary["failed"],
        "skipped_packages": summary.get("skipped_packages", 0),
        "workers": summary.get("workers", 1),
        "output_dir": summary["output_dir"],
    }, indent=2))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
