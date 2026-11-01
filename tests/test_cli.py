"""End-to-end CLI tests against the bundled examples, plus JSON / gating."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

from dockseal.cli import main, audit_path
from dockseal.report import render_json

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.join(os.path.dirname(HERE), "examples")
VULN = os.path.join(EXAMPLES, "Dockerfile.vulnerable")
HARD = os.path.join(EXAMPLES, "Dockerfile.hardened")


def run_main(argv):
    buf = io.StringIO()
    code = 0
    with redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


class TestVulnerable(unittest.TestCase):
    def test_blocks_with_expected_rules(self):
        code, out = run_main([VULN])
        self.assertEqual(code, 2)
        for rule in ("DS-001", "DS-003", "DS-004", "DS-005", "DS-006",
                     "DS-007", "DS-009", "DS-010", "DS-011", "DS-012",
                     "DS-013", "DS-014"):
            self.assertIn(rule, out, f"expected {rule} in vulnerable audit")
        # secret material must never be printed
        self.assertNotIn("0123456789abcdef0123", out)
        self.assertIn("<masked>", out)

    def test_directory_scan_finds_dockerignore_gap(self):
        # examples/ *has* a .dockerignore; a tmp copy without it must trip DS-008
        with tempfile.TemporaryDirectory() as td:
            for name in ("Dockerfile.hardened",):
                shutil.copy(os.path.join(EXAMPLES, name), os.path.join(td, "Dockerfile"))
            code, out = run_main([td])
            self.assertEqual(code, 1)
            self.assertIn("DS-008", out)


class TestHardened(unittest.TestCase):
    def test_hardened_passes(self):
        code, out = run_main([HARD])
        self.assertEqual(code, 0, out)
        self.assertIn("PASS", out)


class TestJson(unittest.TestCase):
    def test_json_shape(self):
        results = audit_path(VULN) + audit_path(HARD)
        payload = json.loads(render_json(results))
        self.assertEqual(payload["tool"], "dockseal")
        self.assertEqual(payload["worst_verdict"], "BLOCK")
        vuln = next(t for t in payload["targets"] if t["target"].endswith("vulnerable"))
        self.assertGreater(vuln["score"], 50)
        self.assertGreater(vuln["n_critical"], 0)
        hardened = next(t for t in payload["targets"] if t["target"].endswith("hardened"))
        self.assertEqual(hardened["score"], 0)

    def test_json_flag(self):
        code, out = run_main(["--json", VULN])
        self.assertEqual(code, 2)
        payload = json.loads(out)
        self.assertEqual(payload["targets"][0]["verdict"], "BLOCK")


class TestGradeGate(unittest.TestCase):
    def test_min_grade_fails_bad_build(self):
        code, _ = run_main(["--min-grade", "A", VULN])
        self.assertEqual(code, 2)

    def test_min_grade_passes_good_build(self):
        code, _ = run_main(["--min-grade", "B", HARD])
        self.assertEqual(code, 0)


class TestDirScan(unittest.TestCase):
    def test_examples_dir_finds_variant_names(self):
        # examples/ contains Dockerfile.vulnerable / Dockerfile.hardened variants
        code, out = run_main([EXAMPLES])
        self.assertEqual(code, 2)          # vulnerable file drags verdict to BLOCK
        self.assertIn("Dockerfile.hardened", out)
        self.assertIn("Dockerfile.vulnerable", out)
        # examples/ has a .dockerignore, so DS-008 must NOT appear
        self.assertNotIn("DS-008", out)

    def test_dir_without_dockerfile_exit_64(self):
        with tempfile.TemporaryDirectory() as td:
            code, _ = run_main([td])
            self.assertEqual(code, 64)


class TestCliErrors(unittest.TestCase):
    def test_missing_path(self):
        buf = io.StringIO()
        code = 0
        with redirect_stdout(buf):
            try:
                code = main(["/nonexistent/nope"])
            except SystemExit as e:
                code = e.code
        self.assertEqual(code, 64)

    def test_dir_without_dockerfile_reports_error(self):
        with tempfile.TemporaryDirectory() as td:
            results = audit_path(td)
            self.assertTrue(results[0].error)


if __name__ == "__main__":
    unittest.main()

