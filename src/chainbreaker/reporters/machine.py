"""JSON, SARIF and Markdown output."""
from __future__ import annotations

import json
from typing import Dict

from .. import __version__
from ..engine import Analysis
from ..models import CAPABILITIES, cap_label
from ..rules import RULES

REPO_URL = "https://github.com/rhizzyxvaici171-cloud/chainbreaker"
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_dict(a: Analysis, target: str, files: int) -> dict:
    chain_count: Dict[str, int] = {}
    for c in a.chains:
        for fid in c.finding_ids:
            chain_count[fid] = chain_count.get(fid, 0) + 1
    findings = []
    for f in a.findings:
        d = f.to_dict()
        d["chains"] = chain_count.get(f.id, 0)
        findings.append(d)
    return {
        "tool": {"name": "chainbreaker", "version": __version__, "url": REPO_URL},
        "target": target,
        "files_scanned": files,
        "assumptions": a.assumptions,
        "exposure": a.exposure,
        "summary": {
            "findings": len(a.findings),
            "chains": len(a.chains),
            "critical_chains": sum(1 for c in a.chains if c.severity == "critical"),
            "goals_reached": a.goals_reached,
        },
        "capabilities": {k: {"label": c.label, "impact": c.impact} for k, c in CAPABILITIES.items()},
        "findings": findings,
        "chains": [c.to_dict() for c in a.chains],
        "fix_plan": [i.to_dict() for i in a.fix_plan],
    }


def render_json(a: Analysis, target: str, files: int) -> str:
    return json.dumps(to_dict(a, target, files), indent=2)


def render_sarif(a: Analysis, target: str, files: int) -> str:
    rules_used = {f.rule for f in a.findings}
    rules = [
        {
            "id": r.id,
            "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description},
            "help": {"text": r.fix},
            "helpUri": f"{REPO_URL}#rules",
            "properties": {"security-severity": SECURITY_SEVERITY[r.severity], "tags": ["security"]},
        }
        for r in RULES if r.id in rules_used
    ]
    results = []
    for f in a.findings:
        chains = a.chains_for(f.id)
        msg = f"{f.title}: {f.evidence}."
        if chains:
            goals = sorted({g for c in chains for g in c.goals}, key=lambda g: -CAPABILITIES[g].impact)
            msg += (f" Part of {len(chains)} attack chain(s) leading to: "
                    f"{', '.join(cap_label(g) for g in goals)}.")
        msg += f" Fix: {f.fix}"
        results.append({
            "ruleId": f.rule,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(f.line, 1)},
            }}],
            "partialFingerprints": {"chainbreaker/v1": f.id},
            "properties": {"chains": [c.id for c in chains], "security-severity": SECURITY_SEVERITY[f.severity]},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ChainBreaker", "version": __version__,
                                "informationUri": REPO_URL, "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def render_markdown(a: Analysis, target: str, files: int, limit: int = 5) -> str:
    md = ["## ⛓️ ChainBreaker", ""]
    if not a.chains:
        md.append(f"No attack chains found in `{target}` ({len(a.findings)} isolated findings).")
        return "\n".join(md) + "\n"
    crit = sum(1 for c in a.chains if c.severity == "critical")
    md += [
        f"**{len(a.chains)} attack chains** ({crit} critical) from **{len(a.findings)} findings** "
        f"in {files} files. Worst outcome: **{cap_label(a.chains[0].goals[0])}**.",
        "",
        "| | Risk | Outcome | Path |",
        "|---|---|---|---|",
    ]
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
    for c in a.chains[:limit]:
        path = " → ".join(
            (f"{s.title} (`{s.finding.location}`)" if s.finding else f"_{s.title}_") for s in c.steps
        )
        md.append(f"| {icon[c.severity]} | {c.risk} | {' + '.join(cap_label(g) for g in c.goals)} | {path} |")
    if len(a.chains) > limit:
        md.append(f"\n_…and {len(a.chains) - limit} more. See the HTML report for every chain._")
    if a.fix_plan:
        md += ["", "### Fix plan", ""]
        for i, item in enumerate(a.fix_plan, 1):
            closes = ", ".join(cap_label(g) for g in item.closes) or "lowers likelihood"
            md.append(f"{i}. **{item.finding.title}** at `{item.finding.location}`: breaks "
                      f"{item.chains_broken} chain(s), closes {closes}. {item.finding.fix}")
    return "\n".join(md) + "\n"
