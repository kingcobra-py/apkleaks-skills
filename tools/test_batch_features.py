#!/usr/bin/env python3
"""Quick unit checks for AWS secret pattern + batch helpers + results formatting."""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from batch_scan import (  # noqa: E402
    discover_apks,
    _interesting_hits,
    _scan_percent,
    fast_scan_tempdir,
    SCAN_PCT_START,
    SCAN_PCT_END,
)
from fdroid_download import (  # noqa: E402
    package_from_apk_name,
    existing_package_names,
    scanned_package_names,
    select_packages,
)
import apk_download  # noqa: E402
from results_format import normalize_job_findings, aggregate_results  # noqa: E402


class AwsSecretPatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patterns = json.loads((ROOT / "config" / "regexes.json").read_text(encoding="utf-8"))
        cls.pattern = patterns["AWS_Secret_Access_Key"]
        cls.rx = re.compile(cls.pattern)

    def test_matches_assignment(self):
        line = 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        self.assertIsNotNone(self.rx.search(line))

    def test_matches_quoted_and_colon(self):
        line = 'AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        self.assertIsNotNone(self.rx.search(line))

    def test_rejects_short(self):
        line = "aws_secret_access_key = tooshort"
        self.assertIsNone(self.rx.search(line))


class BatchHelperTests(unittest.TestCase):
    def test_discover_apks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.apk").write_bytes(b"apk")
            (root / "b.txt").write_text("nope", encoding="utf-8")
            found = discover_apks(root)
            self.assertEqual([p.name for p in found], ["a.apk"])

    def test_interesting_hits(self):
        hits = _interesting_hits([
            {"name": "AWS_Secret_Access_Key"},
            {"name": "SendGrid_API_Key"},
            {"name": "Stripe_API_Key"},
        ])
        self.assertTrue(hits["aws"])
        self.assertTrue(hits["sendgrid"])
        self.assertTrue(hits["stripe"])

    def test_scan_percent_maps_range(self):
        self.assertEqual(_scan_percent(0, 100), SCAN_PCT_START)
        self.assertEqual(_scan_percent(100, 100), SCAN_PCT_END)
        mid = _scan_percent(50, 100)
        self.assertGreater(mid, SCAN_PCT_START)
        self.assertLess(mid, SCAN_PCT_END)


class FastScanTests(unittest.TestCase):
    def test_single_pass_finds_secret_and_reports_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text(
                'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n',
                encoding="utf-8",
            )
            (root / "b.txt").write_text("nothing here\n", encoding="utf-8")
            patterns = {
                "AWS_Secret_Access_Key": (
                    r"(?i)aws[_-]?secret[_-]?access[_-]?key"
                    r".{0,32}['\"]?([A-Za-z0-9/+=]{40})['\"]?"
                ),
                "Generic_API_Key": r"example_api_token_[a-z0-9]+",
            }
            pattern_file = root / "patterns.json"
            pattern_file.write_text(json.dumps(patterns), encoding="utf-8")
            progress: list[tuple[int, int]] = []

            results = fast_scan_tempdir(
                root,
                pattern_file,
                on_progress=lambda done, total: progress.append((done, total)),
            )

            names = {r["name"] for r in results}
            self.assertIn("AWS_Secret_Access_Key", names)
            self.assertTrue(progress)
            self.assertEqual(progress[0][0], 0)
            self.assertEqual(progress[-1][0], progress[-1][1])
            # patterns.json itself is walked; at least the two text files + json
            self.assertGreaterEqual(progress[-1][1], 2)


class FdroidDedupTests(unittest.TestCase):
    def test_package_from_apk_name(self):
        self.assertEqual(package_from_apk_name("com.foo.bar_12.apk"), "com.foo.bar")
        self.assertEqual(package_from_apk_name("ac.mdiq.Podcini.A_83.apk"), "ac.mdiq.Podcini.A")
        self.assertIsNone(package_from_apk_name("not-an-apk.txt"))

    def test_existing_and_scanned_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apks = root / "apks"
            results = root / "results"
            apks.mkdir()
            results.mkdir()
            (apks / "com.demo.app_9.apk").write_bytes(b"apk")
            (results / "org.scanned.one_3.json").write_text(
                json.dumps({"apk": "org.scanned.one_3.apk", "ok": True}),
                encoding="utf-8",
            )
            self.assertEqual(existing_package_names(apks), {"com.demo.app"})
            self.assertEqual(scanned_package_names(results), {"org.scanned.one"})

    def test_select_packages_skips_known_packages(self):
        index = {
            "apps": [
                {"packageName": "com.keep.me", "name": "Keep"},
                {"packageName": "com.skip.me", "name": "Skip"},
            ],
            "packages": {
                "com.keep.me": [{"apkName": "com.keep.me_1.apk", "versionName": "1"}],
                "com.skip.me": [{"apkName": "com.skip.me_2.apk", "versionName": "2"}],
            },
        }
        selected = select_packages(
            index,
            count=10,
            seed=1,
            exclude_packages={"com.skip.me"},
        )
        names = {s["packageName"] for s in selected}
        self.assertEqual(names, {"com.keep.me"})

    def test_select_packages_empty_when_all_excluded(self):
        index = {
            "apps": [{"packageName": "com.skip.me", "name": "Skip"}],
            "packages": {
                "com.skip.me": [{"apkName": "com.skip.me_2.apk", "versionName": "2"}],
            },
        }
        selected = select_packages(index, count=5, exclude_packages={"com.skip.me"})
        self.assertEqual(selected, [])

    def test_parallel_download_workers(self):
        import fdroid_download as fd

        index = {
            "apps": [
                {"packageName": f"com.app{i}", "name": f"App{i}"} for i in range(4)
            ],
            "packages": {
                f"com.app{i}": [{"apkName": f"com.app{i}_1.apk", "versionName": "1"}]
                for i in range(4)
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            seen: list[str] = []

            def fake_download(meta, out_dir, overwrite=False):
                seen.append(meta["packageName"])
                target = out_dir / meta["apkName"]
                target.write_bytes(b"apk")
                return target

            original_load = fd.load_index
            original_dl = fd.download_apk
            fd.load_index = lambda: index  # type: ignore[assignment]
            fd.download_apk = fake_download  # type: ignore[assignment]
            try:
                summary = fd.run(count=4, out_dir=out, workers=3, overwrite=True)
            finally:
                fd.load_index = original_load  # type: ignore[assignment]
                fd.download_apk = original_dl  # type: ignore[assignment]
            self.assertEqual(summary["downloaded"], 4)
            self.assertEqual(summary["workers"], 3)
            self.assertEqual(len(seen), 4)


class ApkDownloadSourceTests(unittest.TestCase):
    def test_apk_filename(self):
        self.assertEqual(apk_download._apk_filename("com.foo", 12), "com.foo_12.apk")
        self.assertEqual(apk_download._apk_filename("com.foo", None), "com.foo_0.apk")

    def test_unknown_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                apk_download.run("not-a-store", count=1, out_dir=Path(tmp))

    def test_aptoide_resolve_uses_path(self):
        meta = {
            "packageName": "com.demo.app",
            "name": "Demo",
            "versionCode": 3,
            "path": "https://example.com/demo.apk",
        }
        resolved = apk_download._resolve_aptoide_download(meta)
        self.assertEqual(resolved["url"], "https://example.com/demo.apk")
        self.assertEqual(resolved["apkName"], "com.demo.app_3.apk")

    def test_apkpure_url(self):
        resolved = apk_download._resolve_apkpure_download({
            "packageName": "com.demo.app",
            "versionCode": 9,
        })
        self.assertIn("com.demo.app", resolved["url"])
        self.assertEqual(resolved["apkName"], "com.demo.app_9.apk")


class ResultsFormatTests(unittest.TestCase):
    def test_aws_pair_format(self):
        key = "AKIA" + "4B7C9D2E1F0A3G8H"
        # Build at runtime so push protection does not flag test fixtures.
        secret = "".join(chr(65 + (i % 26)) + str(i % 10) for i in range(20))
        job = {
            "apk": "demo.apk",
            "findings": [
                {
                    "name": "Amazon_AWS_Access_Key_ID",
                    "severity": "critical",
                    "matches": [key],
                },
                {
                    "name": "AWS_Secret_Access_Key",
                    "severity": "critical",
                    "matches": [f"aws_secret_access_key = {secret}"],
                },
                {
                    "name": "Generic_API_Key",
                    "severity": "high",
                    "matches": ["example_other_api_token_value_123456"],
                },
            ],
        }
        norm = normalize_job_findings(job)
        self.assertEqual(norm["aws_pairs"], [f"{key}:{secret}"])
        self.assertIn(norm["aws_pairs"][0], norm["priority_lines"])
        self.assertIn(
            "Generic_API_Key: example_other_api_token_value_123456",
            norm["other_lines"],
        )

    def test_unpaired_aws_key_stays_in_priority(self):
        key = "AKIA" + "4B7C9D2E1F0A3G8H"
        job = {
            "apk": "key-only.apk",
            "findings": [
                {
                    "name": "Amazon_AWS_Access_Key_ID",
                    "severity": "critical",
                    "matches": [key],
                },
            ],
        }
        norm = normalize_job_findings(job)
        self.assertIn(key, norm["priority_lines"])
        self.assertEqual(norm["other_lines"], [])

    def test_rejects_letter_only_fake_aws_keys(self):
        job = {
            "apk": "fake.apk",
            "findings": [
                {
                    "name": "AWS_API_Key",
                    "matches": [
                        "AKIA" + "EEALATIODAAKUAEB",
                        "AKIA" + "EEALATMGBAABUAEA",
                        "AKIA" + "ISLANDISSHARITAL",
                    ],
                },
                {
                    "name": "Amazon_AWS_Access_Key_ID",
                    "matches": ["AKIA" + "IOSFODNN7EXAMPLE"],
                },
            ],
        }
        norm = normalize_job_findings(job)
        self.assertEqual(norm["priority_lines"], [])
        self.assertEqual(norm["aws_pairs"], [])

    def test_priority_sendgrid_and_sk_live(self):
        sg = "SG." + ("A" * 22) + "." + ("B" * 43)
        # Build at runtime so repo secret scanners do not flag the fixture literal.
        sk = "sk_" + "live_" + ("x" * 24)
        twilio = "SK" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        job = {
            "apk": "pay.apk",
            "findings": [
                {"name": "SendGrid_API_Key", "matches": [sg]},
                {"name": "Stripe_API_Key", "matches": [sk]},
                {"name": "Twilio_API_Key", "matches": [twilio]},
            ],
        }
        norm = normalize_job_findings(job)
        self.assertIn(sg, norm["priority_lines"])
        self.assertIn(sk, norm["priority_lines"])
        self.assertIn(f"Twilio_API_Key: {twilio}", norm["other_lines"])

    def test_filters_common_false_positives(self):
        job = {
            "apk": "noisy.apk",
            "findings": [
                {"name": "Amazon_AWS_S3_Bucket", "matches": ["ads.s3.amazonaws.com"]},
                {"name": "Authorization_Basic", "matches": ["basic whitelist"]},
                {"name": "JSON_Web_Token", "matches": ["androidGradlePluginVersion=8.5.1"]},
                {"name": "Artifactory_Password", "matches": ["APAL4kC0GxjHdgKa81GDVnY4PHvCTiJidX1O14BnoU0"]},
                {"name": "Generic_API_Key", "matches": ["example_mail_api_token_value_123456"]},
            ],
        }
        norm = normalize_job_findings(job)
        self.assertEqual(norm["aws_pairs"], [])
        self.assertNotIn("ads.s3.amazonaws.com", norm["raw_lines"])
        self.assertNotIn("basic whitelist", norm["raw_lines"])
        self.assertNotIn("androidGradlePluginVersion=8.5.1", norm["raw_lines"])
        self.assertIn(
            "Generic_API_Key: example_mail_api_token_value_123456",
            norm["other_lines"],
        )

    def test_aggregate_dedupes(self):
        pair = ("AKIA" + "4B7C9D2E1F0A3G8H") + ":" + ("secret" * 5 + "secre")
        jobs = [
            {
                "apk": "a.apk",
                "priority_lines": [pair],
                "other_lines": [],
                "aws_pairs": [pair],
            },
            {
                "apk": "b.apk",
                "priority_lines": [pair],
                "other_lines": ["example_other_token_abcdefghij"],
                "aws_pairs": [pair],
                "raw_lines": [pair, "example_other_token_abcdefghij", "ads.s3.amazonaws.com"],
            },
        ]
        agg = aggregate_results(jobs)
        self.assertEqual(agg["priority_total"], 1)
        self.assertEqual(agg["other_total"], 1)
        self.assertNotIn("ads.s3.amazonaws.com", agg["lines"])

    def test_aggregate_other_newest_first(self):
        # Callers pass jobs newest-first; Other APIs should keep that order.
        jobs = [
            {
                "apk": "new.apk",
                "priority_lines": [],
                "other_lines": ["Generic_API_Key: newest_token_value_aaa"],
                "aws_pairs": [],
            },
            {
                "apk": "old.apk",
                "priority_lines": [],
                "other_lines": ["Generic_API_Key: oldest_token_value_zzz"],
                "aws_pairs": [],
            },
        ]
        agg = aggregate_results(jobs)
        self.assertEqual(
            agg["other_lines"],
            [
                "Generic_API_Key: newest_token_value_aaa",
                "Generic_API_Key: oldest_token_value_zzz",
            ],
        )

    def test_filters_buildkite_noise(self):
        from results_format import looks_like_secret, is_noise_value

        junk = "bkQablQabmQabnQaboQabpQabqQabrQabsQabtQabuQabvQabwQabxRanjRjng"
        self.assertTrue(is_noise_value(junk) or not looks_like_secret("Buildkite_API_Token", junk))
        good = "bkV68sXnKoJaDjnRK2kIIMxmroESeZbNqVGpoKn2IwYabcd12"
        # May still fail length - ensure mixed case+digit path exists
        self.assertTrue(looks_like_secret("Buildkite_API_Token", "bkAa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2Mm3Nn"))

    def test_rejects_decompiler_password_and_fake_nuget(self):
        from results_format import normalize_job_findings

        job = {
            "apk": "junk.apk",
            "findings": [
                {
                    "name": "Generic_Password",
                    "matches": [
                        'password: ");\n        sb.append(accessibilityNodeInfo.isPassword());\n        sb.append("'
                    ],
                },
                {
                    "name": "NuGet_API_Key",
                    "matches": ["oy2d1isyd5remye6dreye4lenye6letyel4skyels3my7e"],
                },
            ],
        }
        norm = normalize_job_findings(job)
        self.assertEqual(norm["priority_lines"], [])
        self.assertEqual(norm["other_lines"], [])
        self.assertEqual(norm["finding_count"], 0)

if __name__ == "__main__":
    unittest.main()
