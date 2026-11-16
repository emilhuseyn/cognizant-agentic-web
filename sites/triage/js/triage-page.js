// Triage Desk page: dependency input, advisories from OSV.dev and maintainer desks, VEX decisions.
// The assistant's actions (site-actions.js) call the same methods as the page's own controls.
import { Cvss, OsvMatch } from "../osv-match.js";
import { DependencyParser } from "./parse.js";
import { Vex } from "./vex.js";

const OSV_API = "https://api.osv.dev/v1";

export class TriagePage {
  constructor(desks, fetcher = globalThis.fetch?.bind(globalThis)) {
    this.desks = desks;
    this.fetch = fetcher;
    this.doc = null;
    this.version = 0;
    this.appName = "";
    this.npmText = "";
    this.pypiText = "";
    this.dependencies = [];
    this.warnings = [];
    this.findings = [];
    this.records = new Map();
    this.decisions = new Map();
    this.proposals = [];
    this.contacts = new Map();
    this.peerAnswers = new Map();
    this.checking = false;
    this.checkedAt = null;
    this.error = null;
    this.nextProposal = 1;
  }

  static async load() {
    const base = new URL("../", import.meta.url);
    const desks = await (await fetch(new URL("desks.json", base))).json();
    return new TriagePage(desks);
  }

  // ---------- contacts (spec section 5, observable execution) ----------

  noteContact(origin, purpose) {
    const key = `${origin}|${purpose}`;
    const entry = this.contacts.get(key) || { origin, purpose, count: 0, last: null };
    entry.count++;
    entry.last = new Date().toISOString();
    this.contacts.set(key, entry);
    this.renderContacts();
  }

  // Called by site.js for every consent card the runtime shows.
  notePeerConsent(info, decision) {
    const host = info.peerOrigin;
    const allowed = decision !== "decline";
    this.noteContact(host, `${info.kind === "mcp" ? "MCP service" : "agent network"} "${info.peerLabel}": ${allowed ? `allowed (${decision})` : "declined, nothing sent"}`);
    if (allowed) {
      const desk = this.desks.find(d => new URL(d.networkUrl).host === host);
      if (desk) this.peerAnswers.set(desk.project, { host, at: new Date().toISOString(), request: String(info.requestText || "").slice(0, 300) });
    }
  }

  async getJson(url, init, purpose) {
    const origin = new URL(url).origin;
    this.noteContact(new URL(url).host, purpose);
    const response = await this.fetch(url, init);
    if (!response.ok) throw new Error(`${origin} answered HTTP ${response.status}`);
    return response.json();
  }

  // ---------- input ----------

  setInput({ appName, npmText, pypiText }) {
    if (appName !== undefined) this.appName = String(appName).trim();
    if (npmText !== undefined) this.npmText = String(npmText);
    if (pypiText !== undefined) this.pypiText = String(pypiText);
  }

  async loadDemo() {
    const base = new URL("../demo/", import.meta.url);
    const [npm, pypi] = await Promise.all([
      this.fetch(new URL("package.json", base)).then(r => r.text()),
      this.fetch(new URL("requirements.txt", base)).then(r => r.text()),
    ]);
    this.setInput({ appName: "harbor-notes (demo app)", npmText: npm, pypiText: pypi });
    this.renderInput();
    return this.runCheck();
  }

  // ---------- the check ----------

  async runCheck() {
    if (this.checking) return { ok: false, reason: "A check is already running." };
    this.checking = true;
    this.error = null;
    this.renderStatus("Checking dependencies…");
    try {
      const npm = DependencyParser.parseNpm(this.npmText);
      const pypi = DependencyParser.parseRequirements(this.pypiText);
      this.dependencies = [...npm.dependencies, ...pypi.dependencies];
      this.warnings = [...npm.warnings, ...pypi.warnings];
      if (!this.dependencies.length) {
        this.findings = [];
        this.bump();
        return { ok: false, reason: "No pinned dependencies to check. Paste package.json, package-lock.json or requirements.txt with exact versions." };
      }
      const deskDeps = this.dependencies.filter(dep => this.deskFor(dep));
      const osvDeps = this.dependencies.filter(dep => !this.deskFor(dep));
      const found = [];
      found.push(...await this.fromOsv(osvDeps));
      found.push(...await this.fromDesks(deskDeps));
      this.findings = TriagePage.mergeAliases(found).sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || a.package.localeCompare(b.package));
      this.checkedAt = new Date().toISOString();
      // Decisions for findings that are gone stay in memory but drop out of the export.
      this.bump();
      return { ok: true, dependencies: this.dependencies.length, findings: this.findings.length };
    } catch (error) {
      this.error = `The check could not finish: ${error.message}. Nothing was recorded.`;
      this.bump();
      return { ok: false, reason: this.error };
    } finally {
      this.checking = false;
      this.renderStatus();
    }
  }

  // One finding per vulnerability and package: OSV lists the same issue under several ids
  // (GHSA, PYSEC, CVE). Keep the record with a CVSS score, preferring GHSA, and keep the rest as aliases.
  static mergeAliases(found) {
    const groups = [];
    for (const f of found) {
      const names = new Set([f.advisoryId, ...f.aliases]);
      const pkg = `${f.ecosystem}|${f.package}@${f.version}`;
      const group = groups.find(g => g.pkg === pkg && [...names].some(n => g.names.has(n)));
      if (group) {
        group.items.push(f);
        names.forEach(n => group.names.add(n));
      } else {
        groups.push({ pkg, names, items: [f] });
      }
    }
    return groups.map(g => {
      const rank = f => (f.desk ? 4 : 0) + (f.score !== null ? 2 : 0) + (f.advisoryId.startsWith("GHSA-") ? 1 : 0);
      const best = [...g.items].sort((a, b) => rank(b) - rank(a))[0];
      const aliases = [...g.names].filter(n => n !== best.advisoryId);
      const fixedIn = [...new Set(g.items.flatMap(i => i.fixedIn))];
      return { ...best, aliases, fixedIn: best.fixedIn.length ? best.fixedIn : fixedIn };
    });
  }

  deskFor(dep) {
    return this.desks.find(d => d.ecosystem === dep.ecosystem && OsvMatch.normalName(d.ecosystem, d.project) === OsvMatch.normalName(dep.ecosystem, dep.name)) || null;
  }

  async fromOsv(deps) {
    if (!deps.length) return [];
    const queries = deps.map(d => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version }));
    const batch = await this.getJson(`${OSV_API}/querybatch`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ queries }),
    }, "OSV.dev: which advisories affect these versions (package names and versions only)");
    const ids = new Set();
    (batch.results || []).forEach(r => (r.vulns || []).forEach(v => ids.add(v.id)));
    await this.loadRecords([...ids]);
    const out = [];
    (batch.results || []).forEach((r, i) => {
      for (const v of r.vulns || []) {
        const record = this.records.get(v.id);
        if (record) out.push(this.finding(record, deps[i], "OSV.dev", null));
      }
    });
    return out;
  }

  async loadRecords(ids) {
    const missing = ids.filter(id => !this.records.has(id));
    let next = 0;
    const worker = async () => {
      while (next < missing.length) {
        const id = missing[next++];
        try {
          this.records.set(id, await this.getJson(`${OSV_API}/vulns/${encodeURIComponent(id)}`, undefined, "OSV.dev: advisory details"));
        } catch (error) {
          this.records.set(id, { id, summary: `(details could not be loaded: ${error.message})`, affected: [] });
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(6, missing.length) }, worker));
  }

  async fromDesks(deps) {
    const out = [];
    for (const dep of deps) {
      const desk = this.deskFor(dep);
      const index = await this.getJson(desk.feedUrl, undefined, `${desk.label}: published OSV feed`);
      for (const item of index.records || []) {
        const url = new URL(item.url, desk.feedUrl).href;
        let record = this.records.get(item.id);
        if (!record) {
          record = await this.getJson(url, undefined, `${desk.label}: advisory record`);
          this.records.set(item.id, record);
        }
        if (OsvMatch.affects(record, dep.ecosystem, dep.name, dep.version)) out.push(this.finding(record, dep, desk.label, desk));
      }
    }
    return out;
  }

  finding(record, dep, source, desk) {
    const sev = OsvMatch.severity(record);
    const score = sev.score;
    return {
      key: `${record.id}|${dep.ecosystem}|${dep.name}@${dep.version}`,
      advisoryId: record.id,
      aliases: record.aliases || [],
      summary: record.summary || (record.details || "").slice(0, 140),
      package: dep.name,
      ecosystem: dep.ecosystem,
      version: dep.version,
      direct: dep.direct,
      score,
      rating: Cvss.rating(score) || sev.label || "UNKNOWN",
      fixedIn: OsvMatch.fixedVersions(record, dep.ecosystem, dep.name),
      source,
      link: desk ? `${desk.pageUrl}#adv-${record.id}` : `https://osv.dev/vulnerability/${encodeURIComponent(record.id)}`,
      desk: desk ? { tool: desk.tool, label: desk.label, page: desk.pageUrl, origin: new URL(desk.networkUrl).host } : null,
    };
  }

  bump() {
    this.version++;
    this.render();
  }

  findingByKey(key) {
    return this.findings.find(f => f.key === key) || null;
  }

  // ---------- read operations for the assistant ----------

  getFindings() {
    return {
      ok: true,
      app: this.appName || "(unnamed app)",
      version: this.version,
      checkedAt: this.checkedAt,
      dependencies: this.dependencies.length,
      notes: this.warnings.concat(this.dependencies.filter(d => d.note && d.note !== "transitive").map(d => `${d.name}: ${d.note}`)).slice(0, 10),
      // Kept short: every model call pays for this text on the visitor's key.
      findings: this.findings.map(f => {
        const row = {
          key: f.key,
          advisoryId: f.advisoryId,
          package: `${f.ecosystem}/${f.package}@${f.version}`,
          severity: f.score !== null ? `${f.rating} ${f.score.toFixed(1)}` : f.rating,
          summary: f.summary.length > 90 ? `${f.summary.slice(0, 89)}…` : f.summary,
          fixedIn: f.fixedIn.slice(-2),
          decision: this.decisions.get(f.key)?.status || "none",
        };
        if (f.aliases.length) row.aka = f.aliases.slice(0, 2);
        if (!f.direct) row.transitive = true;
        if (f.desk) row.desk = { askTool: f.desk.tool, name: f.desk.label, page: f.desk.page };
        return row;
      }),
      pendingProposals: this.proposals.map(p => ({ proposalId: p.id, finding: p.findingKey, status: p.status })),
      maintainerDesks: this.desks.map(d => ({ package: `${d.ecosystem}/${d.project}`, askTool: d.tool, name: d.label, page: d.pageUrl })),
      desksAskedThisSession: [...this.peerAnswers.keys()],
      error: this.error,
    };
  }

  getAdvisory(id) {
    const record = this.records.get(id);
    const rows = this.findings.filter(f => f.advisoryId === id);
    if (!record || !rows.length) return { ok: false, reason: `${id} is not among the current findings. Call website_get_findings for the ids.`, field: "advisoryId" };
    const sev = OsvMatch.severity(record);
    const f = rows[0];
    return {
      ok: true,
      advisoryId: id,
      aliases: record.aliases || [],
      summary: record.summary || "",
      details: String(record.details || "").slice(0, 1800),
      cvssVector: sev.vector,
      severity: f.score !== null ? `${f.rating} ${f.score.toFixed(1)}` : f.rating,
      packages: rows.map(r => `${r.package}@${r.version}`),
      fixedIn: f.fixedIn,
      references: (record.references || []).slice(0, 5).map(r => r.url),
      source: f.source,
      maintainerDesk: f.desk ? `Ask ${f.desk.tool} (${f.desk.label}) whether it applies to the visitor's use.` : "This package publishes no maintainer desk.",
    };
  }

  // ---------- staged write: the assistant proposes, the visitor applies ----------

  proposeStatement(args) {
    const finding = this.findingByKey(args.findingKey);
    if (!finding) return { ok: false, reason: "No finding has that key. Read website_get_findings again and use its key.", field: "findingKey" };
    const decision = {
      status: args.status,
      justification: args.justification || undefined,
      impactStatement: (args.impactStatement || "").trim() || undefined,
      actionStatement: (args.actionStatement || "").trim() || undefined,
    };
    const problem = Vex.problem(decision);
    if (problem) return { ok: false, reason: problem, field: "status" };
    const evidence = [];
    for (const item of args.evidence || []) {
      const source = String(item.source || "");
      const text = String(item.text || "").trim().slice(0, 600);
      if (!text) continue;
      if (source === "maintainer desk") {
        if (!finding.desk) return { ok: false, reason: `${finding.package} has no maintainer desk, so it cannot be cited.`, field: "evidence" };
        if (!this.peerAnswersFor(finding.desk.origin)) {
          return { ok: false, reason: `The ${finding.desk.label} desk was not asked in this session, so its answer cannot be cited. Ask ${finding.desk.tool} first, or cite the visitor.`, field: "evidence" };
        }
        evidence.push({ source: finding.desk.label, origin: finding.desk.origin, text });
      } else {
        evidence.push({ source, origin: null, text });
      }
    }
    const proposal = {
      id: `P${this.nextProposal++}`,
      findingKey: finding.key,
      ...decision,
      evidence,
      proposedAt: new Date().toISOString(),
    };
    this.proposals.push(proposal);
    this.bump();
    return {
      ok: true,
      proposalId: proposal.id,
      recorded: false,
      waitingFor: "The visitor applies or discards it on the page, under 'Proposed decisions'. Tell them it is waiting there.",
    };
  }

  peerAnswersFor(host) {
    for (const value of this.peerAnswers.values()) if (value.host === host) return true;
    return false;
  }

  applyProposal(id) {
    const index = this.proposals.findIndex(p => p.id === id);
    if (index === -1) return { ok: false, reason: `No proposal ${id}.` };
    const [proposal] = this.proposals.splice(index, 1);
    this.decisions.set(proposal.findingKey, { ...proposal, decidedAt: new Date().toISOString(), decidedBy: "visitor (proposed by the assistant)" });
    this.bump();
    return { ok: true };
  }

  discardProposal(id) {
    this.proposals = this.proposals.filter(p => p.id !== id);
    this.bump();
    return { ok: true };
  }

  setDecision(key, decision) {
    const finding = this.findingByKey(key);
    if (!finding) return { ok: false, reason: "Unknown finding." };
    if (!decision.status) {
      this.decisions.delete(key);
      this.bump();
      return { ok: true };
    }
    const problem = Vex.problem(decision);
    if (problem) return { ok: false, reason: problem };
    this.decisions.set(key, { ...decision, evidence: decision.evidence || [{ source: "visitor", origin: null, text: "Set by hand on the page." }], decidedAt: new Date().toISOString(), decidedBy: "visitor" });
    this.bump();
    return { ok: true };
  }

  async exportVex(author) {
    const name = (this.appName || "app").replace(/\s*\(.*\)\s*$/, "").trim() || "app";
    const productId = `pkg:generic/${encodeURIComponent(name)}`;
    const statements = this.findings
      .filter(f => this.decisions.has(f.key))
      .map(f => Vex.statement(f, this.decisions.get(f.key), productId));
    return Vex.document({ author, productId, statements, timestamp: new Date().toISOString() });
  }

  // ---------- rendering ----------

  mount(doc) {
    this.doc = doc;
    const q = s => doc.querySelector(s);
    q("#input-form").addEventListener("submit", event => {
      event.preventDefault();
      this.setInput({ appName: q("#app-name").value, npmText: q("#npm-text").value, pypiText: q("#pypi-text").value });
      this.runCheck().then(r => { if (!r.ok) this.renderStatus(r.reason); });
    });
    q("#load-demo").addEventListener("click", () => this.loadDemo());
    q("#clear-input").addEventListener("click", () => {
      this.setInput({ appName: "", npmText: "", pypiText: "" });
      this.dependencies = [];
      this.findings = [];
      this.warnings = [];
      this.renderInput();
      this.bump();
    });
    q("#export-vex").addEventListener("click", () => this.download());
    this.renderInput();
    this.render();
  }

  el(tag, attrs = {}, ...children) {
    const node = this.doc.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "class") node.className = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value);
    }
    for (const child of children) {
      if (child === null || child === undefined || child === false) continue;
      node.append(typeof child === "string" || typeof child === "number" ? this.doc.createTextNode(String(child)) : child);
    }
    return node;
  }

  renderInput() {
    if (!this.doc) return;
    this.doc.querySelector("#app-name").value = this.appName;
    this.doc.querySelector("#npm-text").value = this.npmText;
    this.doc.querySelector("#pypi-text").value = this.pypiText;
  }

  renderStatus(text) {
    const node = this.doc?.querySelector("#check-status");
    if (!node) return;
    if (text) { node.textContent = text; return; }
    if (this.error) { node.textContent = this.error; return; }
    if (!this.checkedAt) { node.textContent = ""; return; }
    const desks = this.findings.filter(f => f.desk).length;
    node.textContent = `${this.dependencies.length} dependencies checked, ${this.findings.length} findings${desks ? `, ${desks} from maintainer desks` : ""}.${this.warnings.length ? ` ${this.warnings.length} note(s) below.` : ""}`;
  }

  render() {
    if (!this.doc) return;
    this.renderStatus();
    this.renderWarnings();
    this.renderFindings();
    this.renderProposals();
    this.renderDecisions();
    this.renderContacts();
  }

  renderWarnings() {
    const host = this.doc.querySelector("#input-warnings");
    host.textContent = "";
    for (const w of this.warnings) host.append(this.el("li", {}, w));
  }

  renderFindings() {
    const body = this.doc.querySelector("#finding-rows");
    const empty = this.doc.querySelector("#findings-empty");
    body.textContent = "";
    empty.hidden = this.findings.length > 0;
    for (const f of this.findings) {
      const decision = this.decisions.get(f.key);
      const select = this.el("select", { "aria-label": `Decision for ${f.advisoryId} in ${f.package}`, onchange: e => this.onPick(f, e.target) },
        this.el("option", { value: "" }, "not decided"),
        ...Vex.STATUSES.map(s => this.el("option", { value: s }, s.replace(/_/g, " "))));
      select.value = decision?.status || "";
      body.append(this.el("tr", {},
        this.el("td", {}, this.el("span", { class: `sev sev-${String(f.rating).toLowerCase()}` }, f.score !== null ? `${f.rating.toLowerCase()} ${f.score.toFixed(1)}` : String(f.rating).toLowerCase())),
        this.el("td", {}, this.el("a", { href: f.link, target: "_blank", rel: "noopener" }, f.advisoryId), this.el("div", { class: "small" }, f.summary)),
        this.el("td", { class: "mono" }, `${f.package}@${f.version}`, f.direct ? null : this.el("div", { class: "small" }, "transitive")),
        this.el("td", { class: "mono" }, f.fixedIn.join(", ") || "none"),
        this.el("td", {}, f.desk ? this.el("span", { class: "desk-tag", title: `Maintainers publish a desk at ${f.desk.origin}` }, f.source) : f.source),
        this.el("td", {}, select, decision ? this.el("div", { class: "small" }, decision.justification ? decision.justification.replace(/_/g, " ") : decision.actionStatement || decision.impactStatement || "") : null)));
    }
  }

  onPick(finding, select) {
    const status = select.value;
    if (!status) { this.setDecision(finding.key, {}); return; }
    let decision = { status };
    if (status === "not_affected") {
      const j = this.doc.defaultView.prompt(`Justification for not_affected (one of: ${Vex.JUSTIFICATIONS.join(", ")})`, "vulnerable_code_not_in_execute_path");
      if (!j) { select.value = this.decisions.get(finding.key)?.status || ""; return; }
      decision.justification = j.trim();
    }
    if (status === "affected") {
      const a = this.doc.defaultView.prompt("What will you do? (action statement)", finding.fixedIn.length ? `Upgrade ${finding.package} to ${finding.fixedIn[finding.fixedIn.length - 1]}.` : "");
      if (!a) { select.value = this.decisions.get(finding.key)?.status || ""; return; }
      decision.actionStatement = a.trim();
    }
    const result = this.setDecision(finding.key, decision);
    if (!result.ok) {
      this.doc.defaultView.alert(result.reason);
      select.value = this.decisions.get(finding.key)?.status || "";
    }
  }

  renderProposals() {
    const host = this.doc.querySelector("#proposal-list");
    const card = this.doc.querySelector("#proposals");
    host.textContent = "";
    card.hidden = this.proposals.length === 0;
    for (const p of this.proposals) {
      const f = this.findingByKey(p.findingKey);
      host.append(this.el("article", { class: "proposal" },
        this.el("h3", {}, `${p.id}: ${f ? `${f.advisoryId} in ${f.package}@${f.version}` : p.findingKey}`),
        this.el("p", {}, this.el("strong", {}, p.status.replace(/_/g, " ")), p.justification ? ` (${p.justification.replace(/_/g, " ")})` : ""),
        p.impactStatement ? this.el("p", {}, `Impact: ${p.impactStatement}`) : null,
        p.actionStatement ? this.el("p", {}, `Action: ${p.actionStatement}`) : null,
        p.evidence.length ? this.el("ul", { class: "evidence" }, ...p.evidence.map(e => this.el("li", {}, this.el("strong", {}, e.source), e.origin ? ` (${e.origin})` : "", `: ${e.text}`))) : null,
        this.el("button", { class: "btn", type: "button", onclick: () => this.applyProposal(p.id) }, "Apply this decision"),
        this.el("button", { class: "btn secondary", type: "button", onclick: () => this.discardProposal(p.id) }, "Discard")));
    }
  }

  renderDecisions() {
    const body = this.doc.querySelector("#decision-rows");
    body.textContent = "";
    const rows = this.findings.filter(f => this.decisions.has(f.key));
    this.doc.querySelector("#decisions-empty").hidden = rows.length > 0;
    this.doc.querySelector("#export-vex").disabled = rows.length === 0;
    for (const f of rows) {
      const d = this.decisions.get(f.key);
      body.append(this.el("tr", {},
        this.el("td", {}, f.advisoryId),
        this.el("td", { class: "mono" }, `${f.package}@${f.version}`),
        this.el("td", {}, d.status.replace(/_/g, " ")),
        this.el("td", {}, d.justification ? d.justification.replace(/_/g, " ") : d.actionStatement || ""),
        this.el("td", { class: "small" }, (d.evidence || []).map(e => `${e.source}${e.origin ? ` (${e.origin})` : ""}`).join("; "))));
    }
  }

  renderContacts() {
    const body = this.doc?.querySelector("#contact-rows");
    if (!body) return;
    body.textContent = "";
    for (const c of this.contacts.values()) {
      body.append(this.el("tr", {}, this.el("td", { class: "mono" }, c.origin), this.el("td", {}, c.purpose), this.el("td", {}, c.count)));
    }
  }

  async download() {
    const author = this.doc.querySelector("#vex-author").value.trim() || "Unknown author";
    const doc = await this.exportVex(author);
    const blob = new Blob([JSON.stringify(doc, null, 2) + "\n"], { type: "application/json" });
    const a = this.el("a", { href: URL.createObjectURL(blob), download: `${(this.appName || "app").replace(/[^a-z0-9._-]+/gi, "-")}.openvex.json` });
    this.doc.body.append(a);
    a.click();
    a.remove();
  }
}

export const App = { page: null };

if (typeof window !== "undefined") {
  App.page = await TriagePage.load();
  App.page.mount(document);
  window.addEventListener("assistant-consent", event => App.page.notePeerConsent(event.detail.info, event.detail.decision));
  App.page.loadDemo();
}
