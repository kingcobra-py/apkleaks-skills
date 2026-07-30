#!/usr/bin/env python3
"""Download APKs from F-Droid, Aptoide, APKPure, or APKMirror."""

from __future__ import annotations

import argparse
import json
import logging
import random
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None

# Ensure sibling imports work when launched as `python tools/apk_download.py`.
_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

# Reuse F-Droid helpers / runner.
from fdroid_download import (  # noqa: E402
    existing_apk_names,
    existing_package_names,
    run as run_fdroid,
    scanned_package_names,
)

LOG = logging.getLogger("apk_download")

SOURCES = ("fdroid", "aptoide", "apkpure", "apkmirror")
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
)
APTOIDE_LIST = "https://ws75.aptoide.com/api/7/listApps"
APTOIDE_META = "https://ws2.aptoide.com/api/7/app/getMeta"
APKPURE_DL = "https://d.apkpure.net/b/APK/{package}?version=latest"
# Soft cap so huge apps (WhatsApp-sized) don't stall the batch scanner.
DEFAULT_MAX_BYTES = 80 * 1024 * 1024
MANIFEST_NAME = "download-manifest.json"
LEGACY_MANIFEST_NAME = "fdroid-manifest.json"


def _http_get(url: str, timeout: int = 120, headers: dict[str, str] | None = None) -> bytes:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = Request(url, headers=h)
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _http_get_json(url: str, timeout: int = 60) -> dict[str, Any]:
    raw = _http_get(url, timeout=timeout, headers={"Accept": "application/json"})
    data = json.loads(raw.decode("utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object from {url}")
    return data


def _http_download(
    url: str,
    target: Path,
    timeout: int = 180,
    max_bytes: int | None = DEFAULT_MAX_BYTES,
) -> Path:
    """Stream download to target (.part then rename). Rejects non-APK / oversized."""
    target.parent.mkdir(parents=True, exist_ok=True)
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urlopen(req, timeout=timeout) as resp:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        clen = resp.headers.get("Content-Length")
        if clen and max_bytes and int(clen) > max_bytes:
            raise OSError(f"APK too large ({clen} bytes > {max_bytes})")
        # Some CDNs omit APK content-type; still accept octet-stream / empty.
        if ctype and "html" in ctype:
            raise OSError(f"Unexpected HTML response from {url}")
        tmp = target.with_suffix(target.suffix + ".part")
        written = 0
        with tmp.open("wb") as fh:
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk:
                    break
                written += len(chunk)
                if max_bytes and written > max_bytes:
                    fh.close()
                    tmp.unlink(missing_ok=True)
                    raise OSError(f"APK too large while downloading (>{max_bytes} bytes)")
                fh.write(chunk)
        if written < 1000:
            tmp.unlink(missing_ok=True)
            raise OSError(f"Download too small ({written} bytes)")
        # ZIP/APK magic
        with tmp.open("rb") as fh:
            magic = fh.read(4)
        if magic[:2] != b"PK":
            tmp.unlink(missing_ok=True)
            raise OSError("Downloaded file is not a ZIP/APK")
        tmp.replace(target)
    return target


def _write_manifest(out_dir: Path, summary: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    text = json.dumps(summary, indent=2)
    (out_dir / MANIFEST_NAME).write_text(text, encoding="utf-8")
    # Keep legacy name so older loop code / ops still work.
    (out_dir / LEGACY_MANIFEST_NAME).write_text(text, encoding="utf-8")


def _empty_summary(
    source: str,
    count: int,
    out_dir: Path,
    workers: int,
    skipped_existing: int,
    skipped_packages: int,
) -> dict[str, Any]:
    return {
        "ok": True,
        "source": source,
        "requested": count,
        "selected": 0,
        "downloaded": 0,
        "failed": 0,
        "skipped_existing": skipped_existing,
        "skipped_packages": skipped_packages,
        "workers": workers,
        "output_dir": str(out_dir),
        "apps": [],
    }


def _apk_filename(package: str, vercode: int | str | None) -> str:
    code = str(vercode if vercode is not None else 0)
    code = re.sub(r"[^\d]", "", code) or "0"
    return f"{package}_{code}.apk"


# ---------------------------------------------------------------------------
# Aptoide discovery (also used by APKPure / APKMirror for package candidates)
# ---------------------------------------------------------------------------


def aptoide_list_page(offset: int, limit: int = 50) -> list[dict[str, Any]]:
    url = f"{APTOIDE_LIST}?store_name=apps&limit={limit}&offset={max(0, offset)}"
    data = _http_get_json(url, timeout=60)
    lst = ((data.get("datalist") or {}).get("list")) or []
    return [x for x in lst if isinstance(x, dict)]


def aptoide_total_apps() -> int:
    data = _http_get_json(f"{APTOIDE_LIST}?store_name=apps&limit=1&offset=0", timeout=60)
    total = ((data.get("datalist") or {}).get("total")) or 0
    try:
        return max(0, int(total))
    except (TypeError, ValueError):
        return 0


def aptoide_get_meta(package: str) -> dict[str, Any]:
    url = f"{APTOIDE_META}?package_name={package}"
    data = _http_get_json(url, timeout=60)
    meta = data.get("data")
    if not isinstance(meta, dict):
        raise OSError(f"Aptoide getMeta missing data for {package}")
    return meta


def discover_packages(
    count: int,
    exclude_packages: set[str],
    seed: int | None = None,
    pages: int = 8,
    page_size: int = 50,
) -> list[dict[str, Any]]:
    """Pick random Aptoide store pages and collect unique package candidates."""
    rng = random.Random(seed)
    total = aptoide_total_apps()
    # Leave room near the end of the catalog.
    max_offset = max(0, total - page_size)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set(exclude_packages)
    attempts = 0
    while len(candidates) < count * 3 and attempts < max(pages, 1):
        attempts += 1
        offset = rng.randint(0, max_offset) if max_offset else 0
        # Align roughly to page_size to reduce overlap.
        offset = (offset // page_size) * page_size
        try:
            apps = aptoide_list_page(offset, limit=page_size)
        except (HTTPError, URLError, OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            LOG.warning("Aptoide list failed offset=%s: %s", offset, exc)
            continue
        rng.shuffle(apps)
        for app in apps:
            pkg = app.get("package") or app.get("packageName")
            if not pkg or not isinstance(pkg, str) or pkg in seen:
                continue
            size = app.get("size")
            try:
                if size is not None and int(size) > DEFAULT_MAX_BYTES:
                    continue
            except (TypeError, ValueError):
                pass
            file_meta = app.get("file") if isinstance(app.get("file"), dict) else {}
            candidates.append({
                "packageName": pkg,
                "name": app.get("name") or pkg,
                "versionName": (file_meta or {}).get("vername") or app.get("vername"),
                "versionCode": (file_meta or {}).get("vercode") or app.get("vercode") or 0,
                "size": size,
                "path": (file_meta or {}).get("path") or "",
            })
            seen.add(pkg)
            if len(candidates) >= count * 3:
                break
    rng.shuffle(candidates)
    return candidates[: max(1, count) * 2]


# ---------------------------------------------------------------------------
# Per-source downloaders
# ---------------------------------------------------------------------------


def _resolve_aptoide_download(meta: dict[str, Any]) -> dict[str, Any]:
    pkg = meta["packageName"]
    path = meta.get("path") or ""
    vercode = meta.get("versionCode") or 0
    if not path:
        detail = aptoide_get_meta(pkg)
        file_meta = detail.get("file") if isinstance(detail.get("file"), dict) else {}
        path = (file_meta or {}).get("path") or (file_meta or {}).get("path_alt") or ""
        vercode = (file_meta or {}).get("vercode") or vercode or 0
        size = detail.get("size") or meta.get("size")
        if size is not None and int(size) > DEFAULT_MAX_BYTES:
            raise OSError(f"APK too large ({size} bytes)")
        meta = {
            **meta,
            "name": detail.get("name") or meta.get("name") or pkg,
            "versionName": (file_meta or {}).get("vername") or meta.get("versionName"),
            "versionCode": vercode,
            "size": size,
            "path": path,
        }
    if not path:
        raise OSError(f"No Aptoide download path for {pkg}")
    apk_name = _apk_filename(pkg, vercode)
    return {**meta, "apkName": apk_name, "url": path}


def _resolve_apkpure_download(meta: dict[str, Any]) -> dict[str, Any]:
    pkg = meta["packageName"]
    vercode = meta.get("versionCode") or 0
    # Prefer versionCode from Aptoide discovery for stable filenames / dedup.
    if not vercode:
        try:
            detail = aptoide_get_meta(pkg)
            file_meta = detail.get("file") if isinstance(detail.get("file"), dict) else {}
            vercode = (file_meta or {}).get("vercode") or 0
            size = detail.get("size")
            if size is not None and int(size) > DEFAULT_MAX_BYTES:
                raise OSError(f"APK too large ({size} bytes)")
        except Exception:  # noqa: BLE001
            vercode = 0
    apk_name = _apk_filename(pkg, vercode)
    return {
        **meta,
        "apkName": apk_name,
        "versionCode": vercode,
        "url": APKPURE_DL.format(package=pkg),
    }


def _apkmirror_get(url: str, timeout: int = 45) -> bytes:
    """Best-effort APKMirror fetch (Cloudflare often blocks)."""
    try:
        from curl_cffi import requests as cffi_requests  # type: ignore

        resp = cffi_requests.get(url, impersonate="chrome120", timeout=timeout)
        if resp.status_code == 403 or b"Just a moment" in resp.content[:800]:
            raise OSError("APKMirror blocked by Cloudflare challenge")
        if resp.status_code >= 400:
            raise OSError(f"APKMirror HTTP {resp.status_code}")
        return resp.content
    except ImportError:
        pass
    # Plain urllib almost always hits Cloudflare; still try once.
    try:
        return _http_get(url, timeout=timeout)
    except HTTPError as exc:
        if exc.code == 403:
            raise OSError(
                "APKMirror is Cloudflare-protected and unavailable from this host; "
                "use aptoide or apkpure"
            ) from exc
        raise


def _resolve_apkmirror_download(meta: dict[str, Any]) -> dict[str, Any]:
    """Resolve a download URL via APKMirror search page (best-effort)."""
    pkg = meta["packageName"]
    search_url = (
        "https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s="
        + pkg
    )
    html = _apkmirror_get(search_url).decode("utf-8", errors="ignore")
    if "Just a moment" in html[:2000]:
        raise OSError(
            "APKMirror is Cloudflare-protected and unavailable from this host; "
            "use aptoide or apkpure"
        )
    # Find first release link then variant download — site markup shifts often.
    m = re.search(r'href="(/apk/[^"]+/\d+-release/[^"]*)"', html)
    if not m:
        m = re.search(r'href="(/apk/[^"]+-release/[^"]*)"', html)
    if not m:
        raise OSError(f"No APKMirror release found for {pkg}")
    release_url = "https://www.apkmirror.com" + m.group(1)
    release_html = _apkmirror_get(release_url).decode("utf-8", errors="ignore")
    dm = re.search(r'href="(/apk/[^"]+/download/[^"]*)"', release_html)
    if not dm:
        raise OSError(f"No APKMirror download page for {pkg}")
    download_page = "https://www.apkmirror.com" + dm.group(1)
    dl_html = _apkmirror_get(download_page).decode("utf-8", errors="ignore")
    key = re.search(r'href="(/wp-content/themes/APKMirror/download\.php\?[^"]+)"', dl_html)
    if not key:
        key = re.search(r'data-google-vignette[^>]+href="([^"]*download\.php\?[^"]+)"', dl_html)
    if not key:
        raise OSError(f"No APKMirror download.php link for {pkg}")
    href = key.group(1)
    url = href if href.startswith("http") else "https://www.apkmirror.com" + href
    vercode = meta.get("versionCode") or 0
    return {**meta, "apkName": _apk_filename(pkg, vercode), "url": url}


def _run_store_source(
    source: str,
    count: int,
    out_dir: Path,
    seed: int | None,
    overwrite: bool,
    results_dir: Path | None,
    workers: int,
    resolve: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    exclude_names: set[str] = set()
    exclude_pkgs: set[str] = set()
    if not overwrite:
        exclude_names = existing_apk_names(out_dir)
        exclude_pkgs = existing_package_names(out_dir) | scanned_package_names(results_dir)
    workers_n = max(1, min(32, int(workers or 1)))
    skipped_existing = len(exclude_names)
    skipped_packages = len(exclude_pkgs)

    LOG.info("Discovering packages via Aptoide catalog for source=%s", source)
    discovered = discover_packages(count, exclude_pkgs, seed=seed)
    if not discovered:
        summary = _empty_summary(
            source, count, out_dir, workers_n, skipped_existing, skipped_packages
        )
        _write_manifest(out_dir, summary)
        return summary

    selected: list[dict[str, Any]] = []
    for meta in discovered:
        if len(selected) >= count:
            break
        apk_name = _apk_filename(meta["packageName"], meta.get("versionCode"))
        if not overwrite and apk_name in exclude_names:
            continue
        selected.append(meta)

    if not selected:
        summary = _empty_summary(
            source, count, out_dir, workers_n, skipped_existing, skipped_packages
        )
        _write_manifest(out_dir, summary)
        return summary

    LOG.info("Downloading %s APK(s) from %s with %s worker(s)", len(selected), source, workers_n)

    def _one(meta: dict[str, Any]) -> dict[str, Any]:
        try:
            resolved = resolve(meta)
            target = out_dir / resolved["apkName"]
            if target.exists() and not overwrite:
                return {**resolved, "ok": True, "path": str(target), "skipped_duplicate": True}
            path = _http_download(resolved["url"], target)
            return {**resolved, "ok": True, "path": str(path), "skipped_duplicate": False}
        except (HTTPError, URLError, OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            LOG.error("Failed %s: %s", meta.get("packageName"), exc)
            return {**meta, "ok": False, "error": str(exc)}

    results: list[dict[str, Any]] = []
    progress = tqdm(total=len(selected), desc=f"Downloading ({source})", unit="apk") if tqdm else None
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
        "source": source,
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
    _write_manifest(out_dir, summary)
    return summary


def run(
    source: str,
    count: int,
    out_dir: Path,
    seed: int | None = None,
    overwrite: bool = False,
    results_dir: Path | None = None,
    workers: int = 1,
) -> dict[str, Any]:
    source_n = (source or "fdroid").strip().lower()
    if source_n not in SOURCES:
        raise ValueError(f"Unknown source {source!r}; choose from {', '.join(SOURCES)}")

    if source_n == "fdroid":
        summary = run_fdroid(
            count=count,
            out_dir=out_dir,
            seed=seed,
            overwrite=overwrite,
            results_dir=results_dir,
            workers=workers,
        )
        summary = {**summary, "source": "fdroid"}
        _write_manifest(out_dir, summary)
        return summary

    if source_n == "aptoide":
        return _run_store_source(
            "aptoide", count, out_dir, seed, overwrite, results_dir, workers, _resolve_aptoide_download
        )
    if source_n == "apkpure":
        return _run_store_source(
            "apkpure", count, out_dir, seed, overwrite, results_dir, workers, _resolve_apkpure_download
        )
    return _run_store_source(
        "apkmirror", count, out_dir, seed, overwrite, results_dir, workers, _resolve_apkmirror_download
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download N APKs from F-Droid / Aptoide / APKPure / APKMirror",
    )
    parser.add_argument(
        "--source",
        choices=SOURCES,
        default="fdroid",
        help="APK store source (default: fdroid)",
    )
    parser.add_argument("-n", "--count", type=int, default=100, help="Number of APKs (default: 100)")
    parser.add_argument("-o", "--output", default="apks", help="Output directory (default: apks)")
    parser.add_argument("--results", default=None, help="Results dir — skip packages already scanned")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed")
    parser.add_argument("--overwrite", action="store_true", help="Re-download even if file exists")
    parser.add_argument("-j", "--workers", type=int, default=10, help="Parallel workers (default: 10)")
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
            source=args.source,
            count=args.count,
            out_dir=Path(args.output),
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
        "source": summary.get("source"),
        "requested": summary["requested"],
        "downloaded": summary["downloaded"],
        "failed": summary["failed"],
        "skipped_packages": summary.get("skipped_packages", 0),
        "workers": summary.get("workers", 1),
        "output_dir": summary["output_dir"],
    }, indent=2))
    # Partial failures still leave usable APKs — exit 0 if anything downloaded or nothing selected.
    if summary["failed"] and summary["downloaded"] == 0 and summary.get("selected", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
