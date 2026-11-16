// The maintainer desk page: security policy, advisories, a version check and a private report form.
// Generated sites share this file unchanged; everything project-specific is in desk-data.json.
// The assistant's actions (site-actions.js) call the same methods the page's own controls use.
import { Cvss, OsvMatch, Versions } from "./osv-match.js";

export class DeskPage {
  constructor(data) {
    this.data = data;
    this.doc = null;
    this.version = 0;
    this.lastCheck = null;
    this.report = { summary: "", version: "", details: "", impact: "" };
  }

  static async load() {
    const response = await fetch(new URL("./desk-data.json", import.meta.url));
    if (!response.ok) throw new Error(`desk-data.json: HTTP ${response.status}`);
    return new DeskPage(await response.json());
  }

  get ecosystem() {
    return this.data.ecosystem;
  }

  advisoryIds() {
    return this.data.advisories.map(a => a.id);
  }

  // The folder that serves this page; the build-time URL only in Node tests.
  pageUrl() {
    return typeof window !== "undefined" ? new URL("./", import.meta.url).href : this.data.pageUrl;
  }

  // ---- read operations (also used by the assistant) ----

  getPolicy() {
    return {
      ok: true,
      project: this.data.project,
      ecosystem: this.data.ecosystem,
      tagline: this.data.tagline,
      publishedBy: this.data.maintainers,
      fictionalDemoProject: Boolean(this.data.fictional),
      supportedVersions: this.data.supported,
      reportPrivately: {
        email: this.data.report.email,
        acknowledgeWithinDays: this.data.report.acknowledgeDays,
        disclosureAfterDays: this.data.report.disclosureDays,
        include: this.data.report.include,
        form: "The 'Report a vulnerability privately' form on this page opens an email draft; the visitor sends it.",
      },
      outOfScope: this.data.outOfScope,
      advisories: this.data.advisories.map(a => this.advisorySummary(a)),
      deskPage: this.pageUrl(),
      osvFeed: new URL("osv/index.json", this.pageUrl()).href,
    };
  }

  advisorySummary(record) {
    const sev = OsvMatch.severity(record);
    return {
      id: record.id,
      summary: record.summary,
      cvss: sev.score,
      rating: Cvss.rating(sev.score),
      affectedRanges: this.rangeText(record),
      fixedIn: record.database_specific?.desk?.fixedIn || OsvMatch.fixedVersions(record, this.ecosystem, this.data.project).join(", "),
      published: record.published?.slice(0, 10),
    };
  }

  rangeText(record) {
    const parts = [];
    for (const entry of record.affected || []) {
      for (const range of entry.ranges || []) {
        let open = null;
        for (const event of range.events || []) {
          if (event.introduced !== undefined) open = event.introduced;
          else if (event.fixed !== undefined && open !== null) {
            parts.push(open === "0" ? `<${event.fixed}` : `>=${open} <${event.fixed}`);
            open = null;
          } else if (event.last_affected !== undefined && open !== null) {
            parts.push(open === "0" ? `<=${event.last_affected}` : `>=${open} <=${event.last_affected}`);
            open = null;
          }
        }
        if (open !== null) parts.push(open === "0" ? "all versions" : `>=${open}`);
      }
      if (entry.versions?.length) parts.push(entry.versions.join(", "));
    }
    return parts.join("; ");
  }

  supportFor(version) {
    const parsed = this.ecosystem === "PyPI" ? Versions.parsePep440(version) : Versions.parseSemver(version);
    if (!parsed) return null;
    for (const line of this.data.supported) {
      const m = /^(\d+(?:\.\d+)*)\.x( and older)?$/.exec(line.line.trim());
      if (!m) continue;
      const prefix = m[1].split(".").map(Number);
      const head = parsed.release.slice(0, prefix.length);
      while (head.length < prefix.length) head.push(0);
      let cmp = 0;
      for (let i = 0; i < prefix.length && cmp === 0; i++) cmp = head[i] === prefix[i] ? 0 : head[i] < prefix[i] ? -1 : 1;
      if (cmp === 0 || (m[2] && cmp < 0)) return line;
    }
    return null;
  }

  checkVersion(version) {
    const text = String(version || "").trim();
    if (!Versions.isValid(this.ecosystem, text)) {
      return { ok: false, reason: `"${text}" is not a ${this.ecosystem} version number such as ${this.ecosystem === "PyPI" ? "2.0.1" : "3.0.2"}.`, field: "version" };
    }
    const affectedBy = [];
    const notAffectedBy = [];
    for (const record of this.data.advisories) {
      if (OsvMatch.affects(record, this.ecosystem, this.data.project, text)) {
        affectedBy.push({ ...this.advisorySummary(record), conditions: record.database_specific?.desk?.affectedWhen || [] });
      } else {
        notAffectedBy.push(record.id);
      }
    }
    const support = this.supportFor(text);
    this.lastCheck = {
      ok: true,
      version: text,
      supportLine: support ? `${support.line}: ${support.status}. ${support.note}` : "not listed in the supported versions table",
      affectedBy,
      versionOutsideRangesOf: notAffectedBy,
      note: affectedBy.length
        ? "Inside an affected range. Whether the bug is reachable depends on the conditions listed with each advisory."
        : "Outside every published affected range.",
    };
    this.version++;
    this.renderCheck();
    return this.lastCheck;
  }

  getAdvisory(id) {
    const record = this.data.advisories.find(a => a.id === id);
    if (!record) return { ok: false, reason: `No advisory ${id} on this desk. Known: ${this.advisoryIds().join(", ")}.`, field: "id" };
    const desk = record.database_specific?.desk || {};
    return {
      ok: true,
      ...this.advisorySummary(record),
      details: record.details,
      cvssVector: OsvMatch.severity(record).vector,
      affectedWhen: desk.affectedWhen || [],
      notAffectedWhen: desk.notAffectedWhen || [],
      workarounds: desk.workarounds || [],
      vexHint: desk.vexHint || null,
      osvRecord: new URL(`osv/${record.id}.json`, this.pageUrl()).href,
    };
  }

  // ---- write operation: fills the report form; the visitor sends the email ----

  draftReport(args) {
    const summary = String(args.summary || "").trim();
    const version = String(args.affectedVersion || "").trim();
    if (!summary) return { ok: false, reason: "A one-line summary is required.", field: "summary" };
    if (version && !Versions.isValid(this.ecosystem, version)) {
      return { ok: false, reason: `"${version}" is not a ${this.ecosystem} version number.`, field: "affectedVersion" };
    }
    this.report = {
      summary,
      version,
      details: String(args.details || "").trim(),
      impact: String(args.impact || "").trim(),
    };
    this.version++;
    this.renderReport(true);
    return {
      ok: true,
      filledForm: "Report a vulnerability privately",
      to: this.data.report.email,
      subject: this.reportSubject(),
      sent: false,
      next: "The visitor reviews the form and presses 'Open email draft' to send it from their own email.",
    };
  }

  reportSubject() {
    return `[security] ${this.data.project}${this.report.version ? " " + this.report.version : ""}: ${this.report.summary}`.slice(0, 160);
  }

  reportMailto() {
    const body = [
      `Summary: ${this.report.summary}`,
      `Affected version: ${this.report.version || "(not given)"}`,
      "",
      "Details and steps to reproduce:",
      this.report.details || "(not given)",
      "",
      "Impact:",
      this.report.impact || "(not given)",
    ].join("\n");
    return `mailto:${this.data.report.email}?subject=${encodeURIComponent(this.reportSubject())}&body=${encodeURIComponent(body)}`;
  }

  // ---- rendering ----

  mount(doc) {
    this.doc = doc;
    this.renderAdvisories();
    this.renderSupport();
    this.renderReport(false);
    this.renderPublishing();
    const form = doc.querySelector("#check-form");
    form?.addEventListener("submit", event => {
      event.preventDefault();
      const result = this.checkVersion(doc.querySelector("#check-version").value);
      if (!result.ok) this.renderCheckError(result.reason);
    });
    const report = doc.querySelector("#report-form");
    report?.addEventListener("input", () => {
      this.report = {
        summary: doc.querySelector("#report-summary").value,
        version: doc.querySelector("#report-version").value,
        details: doc.querySelector("#report-details").value,
        impact: doc.querySelector("#report-impact").value,
      };
      this.renderReport(false);
    });
  }

  el(tag, attrs = {}, ...children) {
    const node = this.doc.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "class") node.className = value;
      else node.setAttribute(key, value);
    }
    for (const child of children) {
      if (child === null || child === undefined) continue;
      node.append(typeof child === "string" ? this.doc.createTextNode(child) : child);
    }
    return node;
  }

  list(items) {
    const ul = this.el("ul");
    for (const item of items) ul.append(this.el("li", {}, item));
    return ul;
  }

  renderAdvisories() {
    const host = this.doc.querySelector("#advisory-list");
    if (!host) return;
    host.textContent = "";
    for (const record of this.data.advisories) {
      const s = this.advisorySummary(record);
      const desk = record.database_specific?.desk || {};
      const card = this.el("article", { class: "advisory", id: `adv-${record.id}` },
        this.el("header", {},
          this.el("h3", {}, `${record.id}: ${record.summary}`),
          this.el("span", { class: `sev sev-${(s.rating || "none").toLowerCase()}` }, s.cvss !== null ? `CVSS ${s.cvss.toFixed(1)} ${s.rating.toLowerCase()}` : "no score")),
        this.el("p", {}, record.details),
        this.el("dl", {},
          this.el("dt", {}, "Affected versions"), this.el("dd", {}, s.affectedRanges),
          this.el("dt", {}, "Fixed in"), this.el("dd", {}, s.fixedIn || "no fix yet"),
          this.el("dt", {}, "Published"), this.el("dd", {}, s.published || "")),
        this.el("div", { class: "cols" },
          this.el("div", {}, this.el("h4", {}, "You are affected only when"), this.list(desk.affectedWhen || [])),
          this.el("div", {}, this.el("h4", {}, "You are not affected when"), this.list(desk.notAffectedWhen || []))),
        this.el("h4", {}, "Workarounds"), this.list(desk.workarounds || []),
        this.el("p", { class: "small" }, this.el("a", { href: `osv/${record.id}.json` }, "OSV record (JSON)")));
      host.append(card);
    }
  }

  renderSupport() {
    const body = this.doc.querySelector("#support-rows");
    if (!body) return;
    body.textContent = "";
    for (const line of this.data.supported) {
      body.append(this.el("tr", {}, this.el("td", {}, line.line), this.el("td", {}, line.status), this.el("td", {}, line.note)));
    }
  }

  renderCheck() {
    const host = this.doc?.querySelector("#check-result");
    if (!host || !this.lastCheck) return;
    const r = this.lastCheck;
    host.textContent = "";
    host.className = r.affectedBy.length ? "result warn" : "result ok";
    host.append(this.el("p", {}, this.el("strong", {}, `${this.data.project} ${r.version}: `),
      r.affectedBy.length ? `inside the affected range of ${r.affectedBy.length} advisor${r.affectedBy.length === 1 ? "y" : "ies"}.` : "outside every published affected range."));
    host.append(this.el("p", { class: "small" }, `Support: ${r.supportLine}`));
    if (r.affectedBy.length) {
      const ul = this.el("ul");
      for (const a of r.affectedBy) {
        ul.append(this.el("li", {}, this.el("a", { href: `#adv-${a.id}` }, a.id), ` ${a.summary}. Fixed in ${a.fixedIn}. Only when: ${a.conditions.join("; ")}.`));
      }
      host.append(ul);
    }
    const input = this.doc.querySelector("#check-version");
    if (input && input.value !== r.version) input.value = r.version;
  }

  renderCheckError(reason) {
    const host = this.doc?.querySelector("#check-result");
    if (!host) return;
    host.className = "result error";
    host.textContent = reason;
  }

  renderReport(fromAssistant) {
    if (!this.doc) return;
    const fields = { "#report-summary": "summary", "#report-version": "version", "#report-details": "details", "#report-impact": "impact" };
    for (const [selector, key] of Object.entries(fields)) {
      const input = this.doc.querySelector(selector);
      if (input && input.value !== this.report[key]) input.value = this.report[key];
    }
    const link = this.doc.querySelector("#report-send");
    if (link) {
      const ready = Boolean(this.report.summary.trim());
      link.setAttribute("href", ready ? this.reportMailto() : "#report-form");
      link.setAttribute("aria-disabled", ready ? "false" : "true");
    }
    const note = this.doc.querySelector("#report-note");
    if (note && fromAssistant) {
      note.textContent = "The assistant filled in this form. Check every field, then press Open email draft to send it from your own email.";
      this.doc.querySelector("#report")?.scrollIntoView?.({ behavior: "smooth", block: "start" });
    }
  }

  renderPublishing() {
    const set = (selector, text, href) => {
      const node = this.doc.querySelector(selector);
      if (!node) return;
      node.textContent = text;
      if (href) node.setAttribute("href", href);
    };
    const networkUrl = new URL(this.data.network, this.pageUrl()).href;
    set("#pub-network", networkUrl);
    set("#pub-manifest", new URL("agent-manifest.json", this.pageUrl()).href, "agent-manifest.json");
    set("#pub-feed", new URL("osv/index.json", this.pageUrl()).href, "osv/index.json");
  }
}

export const App = { page: null };

if (typeof window !== "undefined") {
  App.page = await DeskPage.load();
  App.page.mount(document);
}
