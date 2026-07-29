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

from batch_scan import discover_apks, _interesting_hits  # noqa: E402
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


class ResultsFormatTests(unittest.TestCase):
    def test_aws_pair_format(self):
        job = {
            "apk": "demo.apk",
            "findings": [
                {
                    "name": "Amazon_AWS_Access_Key_ID",
                    "severity": "critical",
                    "matches": ["AKIAIOSFODNN7EXAMPLE"],
                },
                {
                    "name": "AWS_Secret_Access_Key",
                    "severity": "critical",
                    "matches": [
                        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    ],
                },
                {
                    "name": "Generic_API_Key",
                    "severity": "high",
                    "matches": ["example_other_api_token_value_123456"],
                },
            ],
        }
        norm = normalize_job_findings(job)
        self.assertEqual(
            norm["aws_pairs"],
            ["AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
        )
        self.assertIn(norm["aws_pairs"][0], norm["priority_lines"])
        self.assertIn("example_other_api_token_value_123456", norm["other_lines"])

    def test_priority_sendgrid_and_sk_live(self):
        sg = "SG." + ("A" * 22) + "." + ("B" * 43)
        # Build at runtime so repo secret scanners do not flag the fixture literal.
        sk = "sk_" + "live_" + ("x" * 24)
        twilio = "SK" + ("ab" * 16)
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
        self.assertIn(twilio, norm["other_lines"])

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
        self.assertIn("example_mail_api_token_value_123456", norm["other_lines"])

    def test_aggregate_dedupes(self):
        pair = "AKIAIOSFODNN7EXAMPLE:secretsecretsecretsecretsecretsecre"
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


if __name__ == "__main__":
    unittest.main()
