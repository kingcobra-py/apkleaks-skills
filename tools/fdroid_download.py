#!/usr/bin/env python3
"""Download N open-source APKs from the official F-Droid repository."""

from __future__ import annotations

import argparse
import io
import json
import logging
import random
import sys
import zipfile
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


def select_packages(index: dict, count: int, seed: int | None = None) -> list[dict]:
    apps = index.get("apps") or []
    packages = index.get("packages") or {}
    candidates = []
    for app in apps:
        pkg = app.get("packageName")
        if not pkg or pkg not in packages:
            continue
        versions = packages[pkg]
        if not versions:
            continue
        # Prefer the first listed package version (usually newest in index-v1).
        ver = versions[0]
        apk_name = ver.get("apkName")
        if not apk_name:
            continue
        candidates.append({
            "packageName": pkg,
            "name": app.get("name") or pkg,
            "apkName": apk_name,
            "versionName": ver.get("versionName"),
            "size": ver.get("size"),
        })
    if not candidates:
        raise RuntimeError("No downloadable packages found in F-Droid index")

    rng = random.Random(seed)
    rng.shuffle(candidates)
    return candidates[: max(1, count)]


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


def run(count: int, out_dir: Path, seed: int | None = None, overwrite: bool = False) -> dict:
    index = load_index()
    selected = select_packages(index, count, seed=seed)
    results = []
    iterator = tqdm(selected, desc="Downloading APKs", unit="apk") if tqdm else selected
    for meta in iterator:
        try:
            path = download_apk(meta, out_dir, overwrite=overwrite)
            results.append({**meta, "ok": True, "path": str(path)})
        except (HTTPError, URLError, OSError, TimeoutError) as exc:
            LOG.error("Failed %s: %s", meta["packageName"], exc)
            results.append({**meta, "ok": False, "error": str(exc)})

    summary = {
        "ok": True,
        "requested": count,
        "selected": len(selected),
        "downloaded": sum(1 for r in results if r.get("ok")),
        "failed": sum(1 for r in results if not r.get("ok")),
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
    parser.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible selection")
    parser.add_argument("--overwrite", action="store_true", help="Re-download even if file exists")
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

    try:
        summary = run(args.count, Path(args.output), seed=args.seed, overwrite=args.overwrite)
    except Exception as exc:  # noqa: BLE001
        LOG.error("%s", exc)
        return 1

    print(json.dumps({
        "ok": summary["ok"],
        "requested": summary["requested"],
        "downloaded": summary["downloaded"],
        "failed": summary["failed"],
        "output_dir": summary["output_dir"],
    }, indent=2))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
