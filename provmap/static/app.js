"use strict";
let R = null, sim = null, focus = null, curTab = "blast";
const SEVR = { critical: 4, high: 3, medium: 2, low: 1 };
const short = (id) => id.replace(/@[^@]*$/, "");

async function scan(demo) {
  if (demo) { R = await api("/api/demo"); render(); return; }
  const f = $("#file").files[0];
  if (!f) { toast("Choose a lockfile first"); return; }
  R = await api("/api/analyze", { json: { filename: f.name, content: await f.text(), provenance: $("#prov").value } });
  render();
}

function worst(n) { return n.vulns.reduce((m, v) => Math.max(m, SEVR[v.severity] || 0), 0); }

function render() {
  const s = R.summary;
  $("#stats").hidden = false; $("#exportCard").hidden = false;
  const sevTxt = ["critical", "high", "medium", "low"].filter((k) => s.by_severity[k]).map((k) => `${s.by_severity[k]} ${k}`).join(" · ") || "none";
  $("#stats").innerHTML = [["Packages", `${s.packages}`, `${s.direct} direct · depth ${s.max_depth}`], ["Advisories", s.advisories, sevTxt],
    ["Vulnerable packages", s.vulnerable_packages, ""], ["Provenance signals", Object.values(s.signals).reduce((a, b) => a + b, 0), `${s.install_scripts} install scripts`]]
    .map(([l, v, sub]) => `<div class="card stat"><div class="v">${v}</div><div class="l">${l}${sub ? ` · ${esc(sub)}` : ""}</div></div>`).join("");
  const msgs = [...R.errors, ...(R.note ? [R.note] : []), ...(R.unpinned.length ? [`${R.unpinned.length} unpinned requirement(s) skipped: ${R.unpinned.slice(0, 5).join(", ")}`] : [])];
  $("#msg").innerHTML = msgs.length ? `<div class="banner">${msgs.map(esc).join("<br>")}</div>` : "";
  $("#findings").innerHTML = R.findings.length ? R.findings.map((f, i) => `
    <div class="f" data-i="${i}"><span class="sev sev-${esc(f.vuln_severity)}">${esc(f.vuln_severity)}</span> ${f.vuln_score ?? ""}
      <b>${esc(f.name)}</b> <span class="mono">${esc(f.version)}</span>${f.dev ? ' <span class="badge b-muted">dev</span>' : ""}
      <div class="muted">${esc(f.vuln_summary)}</div>
      <div class="muted mono">${esc(f.vuln_id)} · depth ${f.depth} · ${f.paths.length}${f.paths_truncated ? "+" : ""} path(s)</div></div>`).join("")
    : '<div class="empty">No known vulnerabilities in OSV for these versions.</div>';
  $$("#findings .f").forEach((el) => el.onclick = () => setFocus(+el.dataset.i));
  drawGraph();
  setFocus(null);
  renderTab(curTab);
}

function drawGraph() {
  const el = $("#graph");
  el.innerHTML = "";
  const W = el.clientWidth, H = el.clientHeight;
  const nodes = R.nodes.map((n) => ({ ...n }));
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const links = R.edges.filter(([a, b]) => byId[a] && byId[b]).map(([a, b]) => ({ source: a, target: b }));
  const deg = {}; links.forEach((l) => { deg[l.source] = (deg[l.source] || 0) + 1; });
  const color = (n) => n.root ? cssVar("--accent") : worst(n) >= 3 ? cssVar("--bad") : worst(n) >= 1 ? cssVar("--warn") : n.direct ? cssVar("--g-direct") : cssVar("--g-trans");
  const radius = (n) => n.root ? 14 : n.vulns.length ? 9 : n.direct ? 7 : 4.5 + Math.min(4, (deg[n.id] || 0));
  const svg = d3.select(el).append("svg").attr("viewBox", [0, 0, W, H]);
  const g = svg.append("g");
  const zoom = d3.zoom().scaleExtent([0.2, 5]).on("zoom", (e) => g.attr("transform", e.transform));
  svg.call(zoom);
  svg.append("defs").append("marker").attr("id", "arr").attr("viewBox", "0 -4 8 8").attr("refX", 8).attr("markerWidth", 6).attr("markerHeight", 6).attr("orient", "auto")
    .append("path").attr("d", "M0,-4L8,0L0,4").attr("fill", cssVar("--muted"));
  const link = g.append("g").selectAll("line").data(links).join("line").attr("class", "link").attr("marker-end", "url(#arr)");
  const node = g.append("g").selectAll("g").data(nodes).join("g")
    .attr("class", (n) => `node${n.signals.length ? " signal" : ""}${n.dev ? " dev" : ""}`)
    .call(d3.drag().on("start", (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; }).on("end", (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
  node.append("circle").attr("r", radius).attr("fill", color);
  node.append("text").attr("dy", (n) => radius(n) + 11).attr("text-anchor", "middle").text((n) => (n.root || n.direct || n.vulns.length) ? short(n.id) : "");
  node.append("title").text((n) => `${n.id}${n.vulns.length ? `\n${n.vulns.map((v) => `${v.id} (${v.severity})`).join("\n")}` : ""}${n.signals.length ? `\n⚑ ${n.signals.map((s) => s.title).join("; ")}` : ""}`);
  node.on("click", (e, n) => { const i = R.findings.findIndex((f) => f.package === n.id); if (i >= 0) setFocus(i); });
  if (sim) sim.stop();
  sim = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id((d) => d.id).distance((l) => l.source.root ? 110 : 60).strength(0.6))
    .force("charge", d3.forceManyBody().strength(-320))
    .force("x", d3.forceX(W / 2).strength(0.02)).force("y", d3.forceY((n) => 40 + (n.depth ?? 3) * (H - 80) / Math.max(3, R.summary.max_depth)).strength(0.25))
    .force("collide", d3.forceCollide((n) => radius(n) + 6))
    .stop();
  sim.tick(300);
  const xs = d3.extent(nodes, (n) => n.x), ys = d3.extent(nodes, (n) => n.y);
  const k = Math.min(2, 0.92 * Math.min(W / (xs[1] - xs[0] + 60), H / (ys[1] - ys[0] + 60)));
  svg.call(zoom.transform, d3.zoomIdentity.translate(W / 2, H / 2).scale(k).translate(-(xs[0] + xs[1]) / 2, -(ys[0] + ys[1]) / 2));
  sim.alpha(0.02).restart().on("tick", tick);
  tick();
  function tick() {
      link.each(function (l) {
        const dx = l.target.x - l.source.x, dy = l.target.y - l.source.y, len = Math.hypot(dx, dy) || 1, r = radius(l.target) + 2;
        d3.select(this).attr("x1", l.source.x).attr("y1", l.source.y).attr("x2", l.target.x - dx / len * r).attr("y2", l.target.y - dy / len * r);
      });
      node.attr("transform", (n) => `translate(${n.x},${n.y})`);
  }
  drawGraph.sel = { node, link };
}

function setFocus(i) {
  focus = i;
  $$("#findings .f").forEach((el) => el.classList.toggle("active", +el.dataset.i === i));
  const { node, link } = drawGraph.sel || {};
  if (!node) return;
  if (i === null) {
    $("#graph").classList.remove("focused"); node.classed("hot", false); link.classed("hot", false);
    $("#pathCard").hidden = true; $("#focusLabel").textContent = "Click a finding to trace its propagation paths"; return;
  }
  const f = R.findings[i];
  const onPath = new Set(f.paths.flat()), pairs = new Set();
  f.paths.forEach((p) => p.slice(1).forEach((x, k) => pairs.add(p[k] + ">" + x)));
  $("#graph").classList.add("focused");
  node.classed("hot", (n) => onPath.has(n.id));
  link.classed("hot", (l) => pairs.has(l.source.id + ">" + l.target.id));
  $("#focusLabel").textContent = `${f.vuln_id} in ${f.package}`;
  $("#pathCard").hidden = false;
  $("#paths").innerHTML = `
    <div><span class="sev sev-${esc(f.vuln_severity)}">${esc(f.vuln_severity)}</span> ${f.vuln_score ?? ""} · <b>${esc(f.vuln_id)}</b> ${esc(f.vuln_cve)} · published ${esc(f.vuln_published)}</div>
    <p>${esc(f.vuln_details || f.vuln_summary)}</p>
    <div class="banner"><b>Remedy:</b> ${esc(f.remedy)}</div>
    <h3>${f.paths.length}${f.paths_truncated ? "+" : ""} path(s) from the project root</h3>
    ${f.paths.map((p) => `<div class="path">${p.map((x, k) => `<span class="${k === p.length - 1 ? "vuln" : ""}">${esc(x)}</span>`).join('<span class="arrow">→</span>')}</div>`).join("")}
    ${f.vuln_references.length ? `<h3>References</h3>${f.vuln_references.map((u) => `<div class="small"><a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></div>`).join("")}` : ""}`;
}

function renderTab(tab) {
  curTab = tab;
  $$("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  const el = $("#tab");
  if (!R) { el.innerHTML = '<div class="empty">No data.</div>'; return; }
  if (tab === "blast") {
    el.innerHTML = R.blast_radius.length ? `<p class="small muted">Which direct dependencies bring vulnerable code into the project, and how much code each pulls in.</p>
      <table><thead><tr><th>Direct dependency</th><th>Vulnerable packages</th><th>Advisories</th><th>Worst</th><th>Transitive deps</th></tr></thead><tbody>
      ${R.blast_radius.map((b) => `<tr><td class="mono">${esc(b.direct)}</td><td>${b.packages}</td><td>${b.findings}</td><td><span class="sev sev-${esc(b.max_severity)}">${esc(b.max_severity)}</span></td><td>${b.transitive_size} ${bar(b.transitive_size, Math.max(...R.blast_radius.map((x) => x.transitive_size)))}</td></tr>`).join("")}</tbody></table>`
      : '<div class="empty">No direct dependency brings in a known vulnerability.</div>';
  } else if (tab === "signals") {
    const flagged = R.nodes.filter((n) => n.signals.length).sort((a, b) => b.risk - a.risk);
    el.innerHTML = flagged.length ? `<p class="small muted">Provenance signals are prompts for review, not defects: many excellent packages have a single maintainer.</p>
      <table><thead><tr><th>Package</th><th>Signals</th><th>Maintainers</th><th>Repository</th></tr></thead><tbody>
      ${flagged.map((n) => `<tr><td class="mono">${esc(n.id)}<div>${confBadge(n.risk)}</div></td>
      <td>${n.signals.map((s) => `<div><b>${esc(s.title)}</b> <span class="small muted">${esc(s.explanation)}</span></div>`).join("")}</td>
      <td class="small">${esc(((n.meta || {}).maintainers || []).join(", "))}</td>
      <td class="small">${(n.meta || {}).repository ? `<a href="${esc(n.meta.repository.replace(/^git\+/, "").replace(/\.git$/, ""))}" target="_blank" rel="noopener noreferrer">${esc(n.meta.repository.replace(/^git\+/, ""))}</a>` : "—"}${n.repo ? `<div class="muted">★ ${n.repo.stars} · pushed ${esc(n.repo.pushed_at)}${n.repo.archived ? " · archived" : ""}</div>` : ""}</td></tr>`).join("")}</tbody></table>`
      : '<div class="empty">No provenance signals (or provenance lookups disabled).</div>';
  } else {
    el.innerHTML = `<table><thead><tr><th>Package</th><th>Depth</th><th>Type</th><th>Published</th><th>Latest</th><th>Licence</th></tr></thead><tbody>
      ${R.nodes.filter((n) => !n.root).sort((a, b) => (a.depth ?? 99) - (b.depth ?? 99) || a.id.localeCompare(b.id)).map((n) => `<tr><td class="mono">${esc(n.id)} ${n.vulns.length ? `<span class="badge b-bad">${n.vulns.length} adv.</span>` : ""}</td>
      <td>${n.depth ?? "—"}</td><td class="small">${n.direct ? "direct" : "transitive"}${n.dev ? " · dev" : ""}${n.install_script ? " · install script" : ""}</td>
      <td class="small">${esc((n.meta || {}).published || "")}</td><td class="small mono">${esc((n.meta || {}).latest || "")}</td><td class="small">${esc((n.meta || {}).license || n.license || "")}</td></tr>`).join("")}</tbody></table>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("#scan").onclick = () => busy($("#scan"), () => scan(false));
  $("#demo").onclick = () => busy($("#demo"), () => scan(true));
  $("#clear").onclick = () => setFocus(null);
  $$("#tabs button").forEach((b) => b.onclick = () => renderTab(b.dataset.tab));
  $("#dlJson").onclick = () => download("provenance.json", JSON.stringify(R, null, 2));
  $$("[data-exp]").forEach((b) => b.onclick = async () => {
    const res = await fetch(`/api/export/${b.dataset.exp}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(R) });
    download(`provenance-${b.dataset.exp}`, await res.text(), b.dataset.exp.endsWith(".csv") ? "text/csv" : "text/markdown");
  });
  window.addEventListener("themechange", () => R && (drawGraph(), setFocus(focus)));
  renderTab(curTab);
});
