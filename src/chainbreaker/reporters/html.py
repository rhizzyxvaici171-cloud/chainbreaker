"""Self-contained interactive HTML report (no CDN, no external requests)."""
from __future__ import annotations

import html
import json

from ..engine import Analysis
from .machine import to_dict


def _safe_json(data: dict) -> str:
    # Scanned files are untrusted input: escape anything that could close the script tag.
    return (json.dumps(data, ensure_ascii=True)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def render_html(a: Analysis, target: str, files: int) -> str:
    data = to_dict(a, target, files)
    return (TEMPLATE
            .replace("__TITLE__", html.escape(f"ChainBreaker report: {target}"))
            .replace("__DATA__", _safe_json(data)))


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>__TITLE__</title>
<style>
:root{--bg:#0a0c11;--panel:#11141c;--panel2:#171b26;--line:#252b3a;--text:#e7e9f0;--muted:#8a93a8;
--crit:#ff4d61;--high:#ff9b42;--med:#ffd35c;--low:#58c4ff;--ok:#3ddc97;--tech:#a78bfa;--goal:#ff4d61}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
code,.mono{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:.86em}
header{padding:36px 40px 26px;border-bottom:1px solid var(--line);
 background:radial-gradient(900px 300px at 10% -20%,rgba(255,77,97,.18),transparent),radial-gradient(700px 260px at 90% -30%,rgba(167,139,250,.16),transparent)}
.brand{display:flex;align-items:center;gap:12px;font-weight:700;font-size:22px;letter-spacing:.3px}
.brand svg{width:30px;height:30px}
.sub{color:var(--muted);margin-top:6px}
main{padding:28px 40px 60px;max-width:1400px}
h2{font-size:17px;text-transform:uppercase;letter-spacing:1.4px;color:var(--muted);margin:40px 0 14px;font-weight:600}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.stat .v{font-size:30px;font-weight:700;line-height:1.1}
.stat .k{color:var(--muted);font-size:13px;margin-top:4px}
.stat.worst .v{font-size:18px;color:var(--crit);padding-top:6px}
.badge{display:inline-block;border-radius:6px;padding:2px 8px;font-size:12px;font-weight:700;letter-spacing:.5px;color:#0a0c11}
.critical{background:var(--crit)} .high{background:var(--high)} .medium{background:var(--med)} .low{background:var(--low)}
.fix{list-style:none;padding:0;margin:0;display:grid;gap:10px;counter-reset:fix}
.fix li{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--ok);border-radius:10px;padding:14px 16px 14px 56px;position:relative;counter-increment:fix}
.fix li::before{content:counter(fix);position:absolute;left:16px;top:14px;width:26px;height:26px;border-radius:50%;background:rgba(61,220,151,.15);color:var(--ok);display:grid;place-items:center;font-weight:700}
.fix .t{font-weight:600}.fix .how{color:var(--muted);margin:3px 0 6px}
.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:1px 9px;font-size:12px;color:var(--muted);margin-right:6px}
.pill.ok{color:var(--ok);border-color:rgba(61,220,151,.4)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.toolbar button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer;font:inherit;font-size:13px}
.toolbar button.on{border-color:var(--tech);background:rgba(167,139,250,.14)}
.chain{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:12px;cursor:pointer;transition:border-color .15s}
.chain:hover,.chain.sel{border-color:var(--tech)}
.chain-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.chain-head h3{margin:0;font-size:16px}
.chain-head .meta{color:var(--muted);font-size:13px;margin-left:auto}
.flow{display:flex;align-items:stretch;flex-wrap:wrap;gap:6px;margin-top:14px}
.node{border-radius:9px;padding:9px 12px;max-width:260px;font-size:13.5px;border:1px solid var(--line);background:var(--panel2)}
.node .loc{color:var(--muted);font-size:12px;margin-top:2px}
.node .gain{color:var(--ok);font-size:12px;margin-top:4px}
.node.start{border-style:dashed;color:var(--muted)}
.node.finding{border-color:rgba(255,77,97,.5)}
.node.technique{border-color:rgba(167,139,250,.55);border-style:dashed}
.node.technique .t{color:#cdbcff}
.node.goal{background:rgba(255,77,97,.12);border-color:var(--crit);font-weight:600}
.arrow{align-self:center;color:var(--muted);font-size:18px;padding:0 2px}
#graph-wrap{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:auto;padding:10px}
#graph text{fill:var(--text);font-size:12px}
#graph .n rect{stroke-width:1.2}
#graph .dim{opacity:.12}
#graph path{fill:none;stroke-width:1.4}
.legend{color:var(--muted);font-size:13px;margin:8px 0 0}
.legend span{margin-right:16px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13.5px}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.8px;background:var(--panel2)}
td .ev{color:var(--muted);word-break:break-all}
input[type=search]{background:var(--panel);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:8px 12px;width:320px;max-width:100%;margin-bottom:10px;font:inherit}
.empty{color:var(--ok);font-size:18px;padding:30px;background:var(--panel);border-radius:12px;border:1px solid var(--line)}
footer{color:var(--muted);font-size:13px;padding:20px 40px;border-top:1px solid var(--line)}
footer a{color:var(--tech)}
</style>
</head>
<body>
<header>
  <div class="brand">
    <svg viewBox="0 0 32 32" fill="none" stroke="#ff4d61" stroke-width="2.4" stroke-linecap="round"><rect x="3" y="11" width="12" height="10" rx="5"/><rect x="17" y="11" width="12" height="10" rx="5" stroke="#a78bfa"/><path d="M13 7l6 18" stroke="#e7e9f0"/></svg>
    ChainBreaker
  </div>
  <div class="sub" id="sub"></div>
</header>
<main>
  <div class="stats" id="stats"></div>
  <section id="fix-section"><h2>Fix plan</h2><ol class="fix" id="fixplan"></ol></section>
  <section><h2>Attack chains</h2><div class="toolbar" id="toolbar"></div><div id="chains"></div></section>
  <section id="graph-section"><h2>Attack graph</h2>
    <div id="graph-wrap"><svg id="graph" xmlns="http://www.w3.org/2000/svg"></svg></div>
    <div class="legend"><span style="color:var(--crit)">■ finding in your code</span><span style="color:var(--tech)">■ attacker technique</span><span>● capability gained</span><span>Click a chain above to highlight it.</span></div>
  </section>
  <section><h2>All findings</h2><input type="search" id="filter" placeholder="Filter findings…"><table id="findings"></table></section>
</main>
<footer id="footer"></footer>
<script id="data" type="application/json">__DATA__</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("data").textContent);
const CAPS = D.capabilities;
const label = k => (CAPS[k] || {label: k}).label;
const isGoal = k => (CAPS[k] || {}).impact > 0;
function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return e;
}
const svgEl = (tag, attrs) => { const e = document.createElementNS("http://www.w3.org/2000/svg", tag); for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v); return e; };

document.getElementById("sub").textContent =
  `${D.target} · ${D.files_scanned} files scanned · attacker assumed able to: ${D.assumptions.map(label).join("; ")}`;

// ---- stats
const crit = D.chains.filter(c => c.severity === "critical").length;
const stats = [
  [D.chains.length, "attack chains"], [crit, "critical chains"], [D.findings.length, "findings"],
  [D.fix_plan.length, "fixes to break them"],
];
const statBox = document.getElementById("stats");
for (const [v, k] of stats) statBox.append(el("div", {class: "stat"}, el("div", {class: "v"}, v), el("div", {class: "k"}, k)));
if (D.chains.length) statBox.append(el("div", {class: "stat worst"}, el("div", {class: "v"}, label(D.chains[0].goals[0])), el("div", {class: "k"}, "worst outcome")));

// ---- fix plan
const fixList = document.getElementById("fixplan");
if (!D.fix_plan.length) document.getElementById("fix-section").remove();
for (const f of D.fix_plan) {
  fixList.append(el("li", {},
    el("div", {class: "t"}, f.title, " ", el("span", {class: "mono", style: "color:var(--muted)"}, f.location)),
    el("div", {class: "how"}, f.fix),
    el("span", {class: "pill ok"}, `breaks ${f.chains_broken} chain${f.chains_broken === 1 ? "" : "s"}`),
    el("span", {class: "pill"}, `exposure ${f.exposure_before} → ${f.exposure_after}`),
    f.closes.length ? el("span", {class: "pill"}, "closes: " + f.closes.map(label).join(", ")) : null));
}

// ---- chains
const chainBox = document.getElementById("chains");
let selected = null, filterGoal = null;
function gainsFor(c) {
  let need = new Set(c.goals); const out = [];
  for (let i = c.steps.length - 1; i >= 0; i--) {
    const s = c.steps[i]; const g = s.grants.filter(x => need.has(x));
    out.unshift(g.length ? g : s.grants); s.requires.forEach(r => need.add(r));
  }
  return out;
}
function renderChains() {
  chainBox.replaceChildren();
  if (!D.chains.length) { chainBox.append(el("div", {class: "empty"}, "No attack chains found. Nice.")); return; }
  for (const c of D.chains) {
    if (filterGoal && !c.goals.includes(filterGoal)) continue;
    const starts = [...new Set(c.steps.flatMap(s => s.requires))].filter(r => D.assumptions.includes(r));
    const flow = el("div", {class: "flow"}, el("div", {class: "node start"}, "Attacker: " + starts.map(label).join("; ")));
    const gains = gainsFor(c);
    c.steps.forEach((s, i) => {
      flow.append(el("div", {class: "arrow"}, "→"));
      flow.append(el("div", {class: "node " + s.kind},
        el("div", {class: "t"}, s.title),
        s.kind === "finding" ? el("div", {class: "loc mono"}, `${s.file}:${s.line} · ${s.rule}`) : el("div", {class: "loc"}, "attacker technique"),
        el("div", {class: "gain"}, "⇒ " + gains[i].map(label).join("; "))));
    });
    flow.append(el("div", {class: "arrow"}, "→"));
    flow.append(el("div", {class: "node goal"}, c.goals.map(label).join(" + ")));
    const card = el("div", {class: "chain" + (selected === c.id ? " sel" : ""), onclick: () => select(c.id)},
      el("div", {class: "chain-head"},
        el("span", {class: "badge " + c.severity}, `${c.severity.toUpperCase()} ${c.risk}`),
        el("span", {class: "mono", style: "color:var(--muted)"}, c.id),
        el("h3", {}, "→ " + c.goals.map(label).join(" + ")),
        el("span", {class: "meta"}, `${c.steps.length} step${c.steps.length === 1 ? "" : "s"} · likelihood ${Math.round(c.likelihood * 100)}%`)),
      flow);
    chainBox.append(card);
  }
}
const goals = [...new Set(D.chains.flatMap(c => c.goals))];
const toolbar = document.getElementById("toolbar");
function renderToolbar() {
  toolbar.replaceChildren();
  if (goals.length < 2) return;
  const mk = (g, text) => el("button", {class: filterGoal === g ? "on" : "", onclick: () => { filterGoal = g; renderToolbar(); renderChains(); }}, text);
  toolbar.append(mk(null, `All (${D.chains.length})`));
  for (const g of goals) toolbar.append(mk(g, `${label(g)} (${D.chains.filter(c => c.goals.includes(g)).length})`));
}
function select(id) { selected = selected === id ? null : id; renderChains(); highlight(); }

// ---- graph (layered layout)
const gNodes = new Map(), gEdges = [];
function addNode(id, kind, text, extra) { if (!gNodes.has(id)) gNodes.set(id, Object.assign({id, kind, text, layer: 0, ins: [], outs: []}, extra || {})); return gNodes.get(id); }
for (const c of D.chains) {
  for (const s of c.steps) {
    addNode("s:" + s.id, s.kind, s.title, {loc: s.file ? `${s.file}:${s.line}` : ""});
    for (const r of s.requires) addNode("c:" + r, D.assumptions.includes(r) ? "start" : (isGoal(r) ? "goal" : "cap"), label(r));
    for (const g of s.grants) addNode("c:" + g, isGoal(g) ? "goal" : "cap", label(g));
  }
}
const seenEdge = new Set();
function link(a, b) { const k = a + "|" + b; if (seenEdge.has(k)) return; seenEdge.add(k); gEdges.push([a, b]); gNodes.get(a).outs.push(b); gNodes.get(b).ins.push(a); }
for (const c of D.chains) for (const s of c.steps) {
  for (const r of s.requires) link("c:" + r, "s:" + s.id);
  for (const g of s.grants) link("s:" + s.id, "c:" + g);
}
for (let round = 0; round < 40; round++) {
  let changed = false;
  for (const n of gNodes.values()) {
    if (n.kind === "start") continue;
    const L = n.ins.length ? Math.max(...n.ins.map(i => gNodes.get(i).layer)) + 1 : 0;
    if (L !== n.layer && L < 60) { n.layer = L; changed = true; }
  }
  if (!changed) break;
}
function drawGraph() {
  const svg = document.getElementById("graph");
  if (!gNodes.size) { document.getElementById("graph-section").remove(); return; }
  const layers = [];
  for (const n of gNodes.values()) (layers[n.layer] = layers[n.layer] || []).push(n);
  const W = 190, H = 46, colGap = 70, rowGap = 16;
  layers.forEach((col, li) => col.forEach((n, i) => { n.y = i; }));
  for (let sweep = 0; sweep < 3; sweep++) for (const col of layers) {
    if (!col) continue;
    col.forEach(n => { const p = n.ins.map(i => gNodes.get(i).y); n.bary = p.length ? p.reduce((a, b) => a + b, 0) / p.length : n.y; });
    col.sort((a, b) => a.bary - b.bary).forEach((n, i) => { n.y = i; });
  }
  const maxRows = Math.max(...layers.filter(Boolean).map(c => c.length));
  const height = maxRows * (H + rowGap) + 20;
  layers.forEach((col, li) => { if (!col) return; const off = (height - col.length * (H + rowGap)) / 2;
    col.forEach(n => { n.x = 10 + li * (W + colGap); n.py = off + n.y * (H + rowGap); }); });
  svg.setAttribute("width", layers.length * (W + colGap) + 20); svg.setAttribute("height", height);
  const colors = {finding: "#ff4d61", technique: "#a78bfa", start: "#8a93a8", cap: "#58c4ff", goal: "#ff4d61"};
  for (const [a, b] of gEdges) {
    const A = gNodes.get(a), B = gNodes.get(b);
    const x1 = A.x + W, y1 = A.py + H / 2, x2 = B.x, y2 = B.py + H / 2, mx = (x1 + x2) / 2;
    const stepNode = A.kind === "finding" || A.kind === "technique" ? A : B;
    const p = svgEl("path", {d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`, stroke: colors[stepNode.kind], "stroke-opacity": .55,
      "stroke-dasharray": stepNode.kind === "technique" ? "4 3" : "", "data-a": a, "data-b": b});
    svg.append(p);
  }
  for (const n of gNodes.values()) {
    const g = svgEl("g", {class: "n", "data-id": n.id});
    const isStep = n.kind === "finding" || n.kind === "technique";
    const fill = n.kind === "goal" ? "rgba(255,77,97,.16)" : isStep ? "#171b26" : "#11141c";
    g.append(svgEl("rect", {x: n.x, y: n.py, width: W, height: H, rx: isStep ? 7 : 22, fill, stroke: colors[n.kind],
      "stroke-dasharray": n.kind === "technique" || n.kind === "start" ? "4 3" : ""}));
    const t = n.text.length > 27 ? n.text.slice(0, 26) + "…" : n.text;
    const tx = svgEl("text", {x: n.x + 10, y: n.py + (n.loc ? 19 : 27)}); tx.textContent = t; g.append(tx);
    if (n.loc) { const lt = svgEl("text", {x: n.x + 10, y: n.py + 35, style: "fill:#8a93a8;font-size:10.5px"}); lt.textContent = n.loc.length > 30 ? "…" + n.loc.slice(-29) : n.loc; g.append(lt); }
    const tip = svgEl("title"); tip.textContent = n.text + (n.loc ? "\n" + n.loc : ""); g.append(tip);
    svg.append(g);
  }
}
function highlight() {
  const svg = document.getElementById("graph"); if (!svg) return;
  const chain = D.chains.find(c => c.id === selected);
  const keep = new Set();
  if (chain) for (const s of chain.steps) { keep.add("s:" + s.id); s.requires.forEach(r => keep.add("c:" + r)); s.grants.forEach(g => keep.add("c:" + g)); }
  svg.querySelectorAll("g.n").forEach(g => g.classList.toggle("dim", !!chain && !keep.has(g.dataset.id)));
  svg.querySelectorAll("path").forEach(p => p.classList.toggle("dim", !!chain && !(keep.has(p.dataset.a) && keep.has(p.dataset.b))));
}

// ---- findings table
const table = document.getElementById("findings");
const sevOrder = {critical: 0, high: 1, medium: 2, low: 3};
table.append(el("thead", {}, el("tr", {}, ["Severity", "Finding", "Location", "Evidence", "Chains", "Fix"].map(h => el("th", {}, h)))));
const tbody = el("tbody");
for (const f of [...D.findings].sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity] || b.chains - a.chains)) {
  tbody.append(el("tr", {},
    el("td", {}, el("span", {class: "badge " + f.severity}, f.severity.toUpperCase())),
    el("td", {}, f.title, el("div", {class: "mono", style: "color:var(--muted)"}, f.rule)),
    el("td", {class: "mono"}, `${f.file}:${f.line}`),
    el("td", {}, el("span", {class: "ev mono"}, f.evidence)),
    el("td", {}, f.chains),
    el("td", {}, f.fix)));
}
table.append(tbody);
document.getElementById("filter").addEventListener("input", e => {
  const q = e.target.value.toLowerCase();
  for (const tr of tbody.rows) tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none";
});

document.getElementById("footer").append("Generated by ", el("a", {href: D.tool.url}, `ChainBreaker ${D.tool.version}`),
  ". Secrets are redacted in this report. Findings are heuristics: verify before you rely on them.");
renderToolbar(); renderChains(); drawGraph();
</script>
</body>
</html>
"""
