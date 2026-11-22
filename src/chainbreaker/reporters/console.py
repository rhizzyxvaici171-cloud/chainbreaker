"""Terminal output."""
from __future__ import annotations

from typing import List

from .. import __version__
from ..engine import Analysis
from ..models import cap_label

SEV_STYLE = {"critical": "1;97;41", "high": "1;30;43", "medium": "30;103", "low": "30;106"}
SEV_TEXT = {"critical": "1;91", "high": "1;33", "medium": "93", "low": "96"}


class Paint:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


def render(a: Analysis, target: str, files: int, color: bool = True, limit: int = 8) -> str:
    p = Paint(color)
    out: List[str] = []
    w = out.append

    w("")
    w(p("  ChainBreaker", "1;95") + p(f" {__version__}", "2") + p("  ·  find attack chains, not just vulnerabilities", "2"))
    w(p(f"  target {target}  ·  {files} files  ·  {len(a.findings)} findings  ·  "
        f"assuming attacker can: {', '.join(a.assumptions)}", "2"))
    w("")

    if not a.chains:
        w(p("  No attack chains found.", "1;92") + f" {len(a.findings)} isolated finding(s).")
        _standalone(a, p, w)
        return "\n".join(out) + "\n"

    crit = sum(1 for c in a.chains if c.severity == "critical")
    worst = cap_label(a.chains[0].goals[0])
    w(f"  {p(str(len(a.chains)), '1;97')} attack chains  ·  {p(str(crit), SEV_TEXT['critical'])} critical  ·  "
      f"worst outcome: {p(worst, '1;91')}")
    w("")

    for c in a.chains[:limit]:
        badge = p(f" {c.severity.upper()} {c.risk:>4} ", SEV_STYLE[c.severity])
        goals = " + ".join(cap_label(g) for g in c.goals)
        steps = f"{len(c.steps)} step{'s' if len(c.steps) != 1 else ''}, likelihood {c.likelihood:.0%}"
        w(f"  {badge} {p(c.id, '2')}  {p('→ ' + goals, '1')}   {p(steps, '2')}")
        starts = sorted(set().union(*(s.requires for s in c.steps)) & set(a.assumptions))
        w(p(f"      start  {'; '.join(cap_label(s) for s in starts)}", "2"))
        later_needs = set(c.goals)
        gains_for = []
        for s in reversed(c.steps):
            gains_for.append(sorted(s.grants & later_needs) or sorted(s.grants))
            later_needs |= s.requires
        gains_for.reverse()
        for i, (s, gains) in enumerate(zip(c.steps, gains_for), 1):
            if s.kind == "finding":
                f = s.finding
                loc = p(f"{f.location}  [{f.rule}]", "36")
                w(f"      {i}. {s.title}  {loc}")
            else:
                w(f"      {i}. {p(s.title, '35')}  {p('[technique]', '2')}")
            w(p(f"         ⇒ {'; '.join(cap_label(g) for g in gains)}", "2"))
        w("")
    if len(a.chains) > limit:
        w(p(f"  … {len(a.chains) - limit} more chains (use --all, or --html for the full interactive report)", "2"))
        w("")

    if a.fix_plan:
        w(p("  FIX PLAN", "1;92") + p("  the fewest changes that break the most chains", "2"))
        for i, item in enumerate(a.fix_plan, 1):
            closes = ", ".join(cap_label(g) for g in item.closes) or "lowers likelihood"
            drop = item.exposure_before - item.exposure_after
            w(f"   {i}. {p(item.finding.title, '1')}  {p(item.finding.location, '36')}")
            w(p(f"      {item.finding.fix}", "2"))
            w(f"      {p(f'breaks {item.chains_broken} chain(s)', '92')}  ·  closes: {closes}  ·  "
              f"exposure {item.exposure_before:g} → {item.exposure_after:g} (-{drop:.1f})")
        if a.fix_plan[-1].exposure_after == 0:
            w(p(f"   ✓ After these {len(a.fix_plan)} fixes no attack chain reaches any goal "
                f"(out of {len(a.findings)} findings).", "1;92"))
        w("")
    _standalone(a, p, w)
    return "\n".join(out) + "\n"


def _standalone(a: Analysis, p: Paint, w) -> None:
    rest = a.standalone_findings()
    if not rest:
        return
    w(p(f"  {len(rest)} finding(s) not in the chains above:", "2"))
    for f in rest[:10]:
        w(f"   · {p(f.severity.upper(), SEV_TEXT[f.severity])} {f.title}  {p(f.location, '36')}")
    if len(rest) > 10:
        w(p(f"   · … and {len(rest) - 10} more", "2"))
    w("")
