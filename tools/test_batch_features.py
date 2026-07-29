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
                    "name": "Stripe_API_Key",
                    "severity": "critical",
                    "matches": ["example_payment_token_not_real"],
                },
            ],
        }
        norm = normalize_job_findings(job)
        self.assertEqual(
            norm["aws_pairs"],
            ["AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
        )
        self.assertIn("example_payment_token_not_real", norm["raw_other"])
        self.assertEqual(norm["raw_lines"][0], norm["aws_pairs"][0])

    def test_aggregate_dedupes(self):
        jobs = [
            {
                "apk": "a.apk",
                "raw_lines": ["AKIAEXAMPLE:secretsecretsecretsecretsecretsecre"],
                "aws_pairs": ["AKIAEXAMPLE:secretsecretsecretsecretsecretsecre"],
            },
            {
                "apk": "b.apk",
                "raw_lines": ["AKIAEXAMPLE:secretsecretsecretsecretsecretsecre", "tok_abc"],
                "aws_pairs": ["AKIAEXAMPLE:secretsecretsecretsecretsecretsecre"],
            },
        ]
        agg = aggregate_results(jobs)
        self.assertEqual(agg["total"], 2)
        self.assertEqual(len(agg["aws_pairs"]), 1)


if __name__ == "__main__":
    unittest.main()
