"""The attack-chain engine.

Findings and attacker techniques are edges in a hypergraph over capabilities: an edge fires once
an attacker holds *all* of its required capabilities, and hands over its granted ones. Starting
from what any outsider has, the engine searches forward for the most likely ways to reach each
goal, then works out which fixes break the most chains.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Sequence, Set, Tuple

from .models import CAPABILITIES, Finding, Step, cap_impact, SEVERITY_RANK

S = frozenset

# Generic attacker know-how: no code weakness on their own, but they join findings together.
TECHNIQUES: Tuple[Step, ...] = (
    Step("T1", "technique", "Sign a valid token for any user with the leaked secret",
         S({"jwt_secret", "internet"}), S({"session_forge"}), 0.9),
    Step("T2", "technique", "Mint a token that carries the admin role",
         S({"session_forge"}), S({"admin_access"}), 0.8),
    Step("T3", "technique", "Log in to the exposed database with the leaked credentials",
         S({"db_creds", "db_network"}), S({"db_read", "db_write"}), 0.9),
    Step("T4", "technique", "Read the app's code and config files from disk",
         S({"rce"}), S({"source_read"}), 0.95),
    Step("T5", "technique", "Read database credentials from the process environment",
         S({"rce"}), S({"db_creds"}), 0.8),
    Step("T6", "technique", "Query the database from inside the app's network",
         S({"rce", "db_creds"}), S({"db_read", "db_write"}), 0.9),
    Step("T7", "technique", "Call the cloud provider's API with the stolen keys",
         S({"cloud_creds", "internet"}), S({"cloud_takeover"}), 0.85),
    Step("T8", "technique", "Use the stolen token or password against its service",
         S({"api_token", "internet"}), S({"third_party_abuse"}), 0.75),
    Step("T9", "technique", "Browse and export user records through admin features",
         S({"admin_access"}), S({"db_read"}), 0.5),
)

Path = Tuple[Step, ...]


def likelihood(path: Sequence[Step]) -> float:
    p = 1.0
    for s in path:
        p *= s.confidence
    return p


def _rank(path: Path):
    return (-likelihood(path), len(path), tuple(s.id for s in path))


def finding_steps(findings: Iterable[Finding]) -> List[Step]:
    return [Step(f.id, "finding", f.title, f.requires, f.grants, f.confidence, f) for f in findings]


def solve(steps: Sequence[Step], start: Iterable[str], k: int = 3, max_rounds: int = 64) -> Dict[str, List[Path]]:
    """Return, for every reachable capability, up to ``k`` most likely paths that obtain it."""
    start = set(start)
    best: Dict[str, List[Path]] = {c: [()] for c in start}
    for _ in range(max_rounds):
        changed = False
        for st in steps:
            reqs = sorted(st.requires)
            if not all(r in best for r in reqs):
                continue
            for combo in itertools.product(*(best[r] for r in reqs)):
                merged: List[Step] = []
                ids: Set[str] = set()
                for path in combo:
                    for s in path:
                        if s.id not in ids:
                            ids.add(s.id)
                            merged.append(s)
                if st.id in ids:
                    continue
                for g in st.grants:
                    if g in start or any(g in s.grants for s in merged):
                        continue  # already held, so this step adds nothing for g
                    cand: Path = tuple(merged) + (st,)
                    lst = best.setdefault(g, [])
                    key = tuple(s.id for s in cand)
                    if any(tuple(s.id for s in p) == key for p in lst):
                        continue
                    lst.append(cand)
                    lst.sort(key=_rank)
                    del lst[k:]
                    if cand in lst:
                        changed = True
        if not changed:
            break
    return best


def risk_score(impact: int, prob: float) -> float:
    return round(impact * (0.5 + 0.5 * prob), 1)


def severity_for(risk: float) -> str:
    if risk >= 7:
        return "critical"
    if risk >= 5:
        return "high"
    if risk >= 3:
        return "medium"
    return "low"


@dataclass
class Chain:
    id: str
    goals: List[str]
    steps: Path
    likelihood: float
    risk: float
    severity: str

    @property
    def finding_ids(self) -> Set[str]:
        return {s.id for s in self.steps if s.kind == "finding"}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "goals": self.goals,
            "risk": self.risk,
            "severity": self.severity,
            "likelihood": round(self.likelihood, 3),
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class FixItem:
    finding: Finding
    closes: List[str]
    chains_broken: int
    exposure_before: float
    exposure_after: float

    def to_dict(self) -> dict:
        return {
            "finding": self.finding.id,
            "title": self.finding.title,
            "location": self.finding.location,
            "fix": self.finding.fix,
            "closes": self.closes,
            "chains_broken": self.chains_broken,
            "exposure_before": self.exposure_before,
            "exposure_after": self.exposure_after,
        }


@dataclass
class Analysis:
    findings: List[Finding]
    assumptions: List[str]
    chains: List[Chain] = field(default_factory=list)
    fix_plan: List[FixItem] = field(default_factory=list)
    exposure: float = 0.0

    @property
    def goals_reached(self) -> List[str]:
        seen: List[str] = []
        for c in self.chains:
            for g in c.goals:
                if g not in seen:
                    seen.append(g)
        return seen

    def chains_for(self, finding_id: str) -> List[Chain]:
        return [c for c in self.chains if finding_id in c.finding_ids]

    def standalone_findings(self) -> List[Finding]:
        used = set().union(*(c.finding_ids for c in self.chains)) if self.chains else set()
        return [f for f in self.findings if f.id not in used]


def _goals(best: Dict[str, List[Path]]) -> List[str]:
    return [g for g in best if cap_impact(g) > 0 and best[g] and best[g][0]]


def exposure(best: Dict[str, List[Path]]) -> float:
    """Total risk across reachable goals, using the most likely path to each."""
    return round(sum(risk_score(cap_impact(g), likelihood(best[g][0])) for g in _goals(best)), 1)


def build_chains(best: Dict[str, List[Path]]) -> List[Chain]:
    grouped: Dict[Tuple[str, ...], Tuple[Path, List[str]]] = {}
    for g in _goals(best):
        for path in best[g]:
            key = tuple(s.id for s in path)
            grouped.setdefault(key, (path, []))[1].append(g)
    chains = []
    for path, goals in grouped.values():
        goals.sort(key=lambda g: -cap_impact(g))
        p = likelihood(path)
        risk = risk_score(max(cap_impact(g) for g in goals), p)
        chains.append(Chain("", goals, path, p, risk, severity_for(risk)))
    chains.sort(key=lambda c: (-c.risk, len(c.steps), -c.likelihood))
    for i, c in enumerate(chains, 1):
        c.id = f"C{i}"
    return chains


def plan_fixes(findings: Sequence[Finding], chains: Sequence[Chain], start: Iterable[str],
               max_items: int = 15) -> List[FixItem]:
    """Order fixes so every goal becomes unreachable with as few changes as possible.

    Greedy, one fix at a time. A candidate is judged by, in order: the impact of goals still
    reachable afterwards, how many reported chains survive, then total exposure. Comparing on
    surviving chains keeps the plan moving when a goal has several independent entry points
    and no single fix can close it alone.
    """
    start = list(start)
    candidates = [f for f in findings if f.grants]
    removed: Set[str] = set()
    plan: List[FixItem] = []

    def evaluate(skip: Set[str]):
        steps = finding_steps(f for f in findings if f.id not in skip) + list(TECHNIQUES)
        best = solve(steps, start, k=1)
        goals = set(_goals(best))
        surviving = sum(1 for c in chains if not (c.finding_ids & skip))
        return (sum(cap_impact(g) for g in goals), surviving, exposure(best)), goals

    score, goals_now = evaluate(removed)
    while goals_now and len(plan) < max_items:
        options = []
        for f in candidates:
            if f.id in removed:
                continue
            s, goals = evaluate(removed | {f.id})
            options.append((s, -SEVERITY_RANK.get(f.severity, 0), f.id, f, goals))
        if not options:
            break
        s, _, _, f, goals = min(options, key=lambda o: o[:3])
        if s >= score:
            break
        broken = sum(1 for c in chains if f.id in c.finding_ids and not (c.finding_ids & removed))
        removed.add(f.id)
        closes = sorted(goals_now - goals, key=lambda g: -cap_impact(g))
        plan.append(FixItem(f, closes, broken, score[2], s[2]))
        score, goals_now = s, goals
    return plan


def analyze(findings: Sequence[Finding], assumptions: Iterable[str] = ("internet", "source_read"),
            k: int = 5) -> Analysis:
    assumptions = [a for a in assumptions if a in CAPABILITIES]
    steps = finding_steps(findings) + list(TECHNIQUES)
    best = solve(steps, assumptions, k=k)
    chains = build_chains(best)
    analysis = Analysis(list(findings), assumptions, chains)
    analysis.exposure = exposure(solve(steps, assumptions, k=1))
    analysis.fix_plan = plan_fixes(findings, chains, assumptions)
    return analysis
