"""End-to-end: scan the bundled vulnerable app and check the headline chains and outputs."""
import json
import os
import tempfile
import unittest

import _bootstrap  # noqa: F401
from chainbreaker.cli import main
from chainbreaker.engine import analyze
from chainbreaker.reporters import render_html, render_sarif
from chainbreaker.scanner import scan

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "vulnerable-shop")


class Demo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan(DEMO)
        cls.analysis = analyze(cls.result.findings)

    def test_every_planted_weakness_is_found(self):
        rules = {f.rule for f in self.result.findings}
        for rule in ("CB102", "CB104", "CB201", "CB203", "CB204", "CB205", "CB206", "CB207",
                     "CB301", "CB302", "CB304", "CB401"):
            self.assertIn(rule, rules)

    def test_reaches_host_root_through_the_container(self):
        root = [c for c in self.analysis.chains if "host_root" in c.goals]
        self.assertTrue(root)
        self.assertEqual([s.finding.rule for s in root[0].steps[-2:]], ["CB301", "CB302"])

    def test_leaked_creds_plus_open_port_dump_the_db(self):
        db = [c for c in self.analysis.chains if "db_write" in c.goals and "T3" in [s.id for s in c.steps]]
        self.assertTrue(db)

    def test_fix_plan_ends_with_zero_exposure(self):
        self.assertEqual(self.analysis.fix_plan[0].finding.rule, "CB302")
        self.assertEqual(self.analysis.fix_plan[-1].exposure_after, 0)

    def test_html_escapes_scanned_content(self):
        page = render_html(self.analysis, "<script>alert(1)</script>", self.result.files_scanned)
        self.assertNotIn("<script>alert(1)", page)
        self.assertNotIn("shop_admin_pw", page)  # secrets are redacted

    def test_sarif_is_valid_json(self):
        sarif = json.loads(render_sarif(self.analysis, "demo", self.result.files_scanned))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), len(self.result.findings))

    def test_cli_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.json")
            self.assertEqual(main(["scan", DEMO, "-q", "--json", out, "--fail-on", "critical"]), 1)
            with open(out, encoding="utf-8") as fh:
                self.assertGreater(json.load(fh)["summary"]["chains"], 5)
            clean = os.path.join(tmp, "clean.py")
            with open(clean, "w") as fh:
                fh.write("print('hello')\n")
            self.assertEqual(main(["scan", clean, "-q", "--fail-on", "low"]), 0)


if __name__ == "__main__":
    unittest.main()
