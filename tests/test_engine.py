import unittest

import _bootstrap  # noqa: F401
from chainbreaker.engine import TECHNIQUES, analyze, finding_steps, solve
from chainbreaker.models import Finding


def finding(rule, requires, grants, conf=0.8, line=1):
    return Finding(rule, rule, "high", "x.py", line, "", "fix it", frozenset(requires), frozenset(grants), conf)


class Engine(unittest.TestCase):
    def test_multi_step_chain_to_host_root(self):
        fs = [
            finding("RCE", {"internet"}, {"rce"}),
            finding("ROOT", {"rce"}, {"container_root"}),
            finding("SOCK", {"container_root"}, {"host_root"}),
        ]
        top = analyze(fs).chains[0]
        self.assertEqual(top.goals, ["host_root"])
        self.assertEqual([s.id for s in top.steps], [f.id for f in fs])

    def test_no_chain_without_entry_point(self):
        fs = [finding("ROOT", {"rce"}, {"container_root"}), finding("SOCK", {"container_root"}, {"host_root"})]
        self.assertEqual(analyze(fs).chains, [])

    def test_conjunction_needs_both_requirements(self):
        creds = finding("CREDS", {"source_read"}, {"db_creds"})
        port = finding("PORT", {"internet"}, {"db_network"})
        self.assertNotIn("db_write", analyze([creds]).goals_reached)
        self.assertIn("db_write", analyze([creds, port]).goals_reached)

    def test_private_repo_hides_secrets_until_rce(self):
        secret = finding("JWT", {"source_read"}, {"jwt_secret"})
        self.assertEqual(analyze([secret], ["internet"]).chains, [])
        rce = finding("RCE", {"internet"}, {"rce"})
        chains = analyze([secret, rce], ["internet"]).chains
        admin = [c for c in chains if "admin_access" in c.goals]
        self.assertTrue(admin, "rce -> read source -> leaked secret -> forged admin token")
        self.assertIn("T4", [s.id for s in admin[0].steps])

    def test_more_likely_path_ranks_first(self):
        weak = finding("WEAK", {"internet"}, {"rce"}, conf=0.3, line=1)
        strong = finding("STRONG", {"internet"}, {"rce"}, conf=0.9, line=2)
        best = solve(finding_steps([weak, strong]) + list(TECHNIQUES), ["internet"])
        self.assertEqual(best["rce"][0][-1].id, strong.id)
        self.assertEqual(len(best["rce"]), 2)

    def test_fix_plan_closes_every_goal(self):
        fs = [
            finding("RCE1", {"internet"}, {"rce"}, line=1),
            finding("RCE2", {"internet"}, {"rce"}, line=2),
            finding("ROOT", {"rce"}, {"container_root"}),
            finding("SOCK", {"container_root"}, {"host_root"}),
        ]
        plan = analyze(fs).fix_plan
        self.assertIn(plan[0].finding.rule, {"ROOT", "SOCK"})  # one fix closes the worst outcome
        self.assertIn("host_root", plan[0].closes)
        self.assertEqual(plan[-1].exposure_after, 0)


if __name__ == "__main__":
    unittest.main()
