// Version comparison and OSV range matching, shared by the Triage Desk and every maintainer desk.
// Copied into each site by scripts/build_all.mjs, so each site stays a self-contained bundle.
// npm versions follow SemVer 2.0; PyPI versions follow a practical subset of PEP 440
// (release numbers, a/b/rc pre-releases, .post and .dev). Anything else compares as text.

const PEP440 = /^v?(\d+(?:\.\d+)*)(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?(?:[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+[a-z0-9.]+)?$/i;
const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export class Versions {
  static parseSemver(text) {
    const m = SEMVER.exec(String(text).trim());
    if (!m) return null;
    return { release: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split(".") : null };
  }

  static compareSemver(a, b) {
    const x = Versions.parseSemver(a);
    const y = Versions.parseSemver(b);
    if (!x || !y) return Versions.compareText(a, b);
    for (let i = 0; i < 3; i++) {
      if (x.release[i] !== y.release[i]) return x.release[i] < y.release[i] ? -1 : 1;
    }
    if (!x.pre && !y.pre) return 0;
    if (!x.pre) return 1;
    if (!y.pre) return -1;
    const n = Math.max(x.pre.length, y.pre.length);
    for (let i = 0; i < n; i++) {
      const p = x.pre[i];
      const q = y.pre[i];
      if (p === undefined) return -1;
      if (q === undefined) return 1;
      const pn = /^\d+$/.test(p);
      const qn = /^\d+$/.test(q);
      if (pn && qn && Number(p) !== Number(q)) return Number(p) < Number(q) ? -1 : 1;
      if (pn !== qn) return pn ? -1 : 1;
      if (!pn && p !== q) return p < q ? -1 : 1;
    }
    return 0;
  }

  static parsePep440(text) {
    const m = PEP440.exec(String(text).trim());
    if (!m) return null;
    const preKind = m[2] ? ({ alpha: "a", a: "a", beta: "b", b: "b", c: "rc", rc: "rc", pre: "rc", preview: "rc" })[m[2].toLowerCase()] : null;
    return {
      release: m[1].split(".").map(Number),
      pre: preKind ? [{ a: 0, b: 1, rc: 2 }[preKind], Number(m[3] || 0)] : null,
      post: m[4] ? Number(m[5] || 0) : null,
      dev: m[6] ? Number(m[7] || 0) : null,
    };
  }

  // PEP 440 order: X.devN < X.aN < X.bN < X.rcN < X < X.postN.
  static pep440Key(v) {
    let preKey;
    if (v.pre) preKey = [1, v.pre[0], v.pre[1]];
    else if (v.dev !== null && v.post === null) preKey = [0, 0, 0];
    else preKey = [2, 0, 0];
    const postKey = v.post === null ? -1 : v.post;
    const devKey = v.dev === null ? Infinity : v.dev;
    return { preKey, postKey, devKey };
  }

  static comparePep440(a, b) {
    const x = Versions.parsePep440(a);
    const y = Versions.parsePep440(b);
    if (!x || !y) return Versions.compareText(a, b);
    const n = Math.max(x.release.length, y.release.length);
    for (let i = 0; i < n; i++) {
      const p = x.release[i] || 0;
      const q = y.release[i] || 0;
      if (p !== q) return p < q ? -1 : 1;
    }
    const kx = Versions.pep440Key(x);
    const ky = Versions.pep440Key(y);
    for (let i = 0; i < 3; i++) {
      if (kx.preKey[i] !== ky.preKey[i]) return kx.preKey[i] < ky.preKey[i] ? -1 : 1;
    }
    if (kx.postKey !== ky.postKey) return kx.postKey < ky.postKey ? -1 : 1;
    if (kx.devKey !== ky.devKey) return kx.devKey < ky.devKey ? -1 : 1;
    return 0;
  }

  static compareText(a, b) {
    const x = String(a);
    const y = String(b);
    return x === y ? 0 : x < y ? -1 : 1;
  }

  static compare(ecosystem, a, b) {
    return String(ecosystem).toLowerCase() === "pypi" ? Versions.comparePep440(a, b) : Versions.compareSemver(a, b);
  }

  static isValid(ecosystem, text) {
    return String(ecosystem).toLowerCase() === "pypi" ? Versions.parsePep440(text) !== null : Versions.parseSemver(text) !== null;
  }
}

export class OsvMatch {
  // True when `version` of `name` in `ecosystem` falls in one of the record's affected entries.
  static affects(record, ecosystem, name, version) {
    return OsvMatch.matchingEntries(record, ecosystem, name, version).length > 0;
  }

  static matchingEntries(record, ecosystem, name, version) {
    const out = [];
    for (const entry of record.affected || []) {
      const pkg = entry.package || {};
      if (String(pkg.ecosystem).toLowerCase() !== String(ecosystem).toLowerCase()) continue;
      if (OsvMatch.normalName(ecosystem, pkg.name) !== OsvMatch.normalName(ecosystem, name)) continue;
      if ((entry.versions || []).includes(version) || OsvMatch.inRanges(entry.ranges || [], ecosystem, version)) out.push(entry);
    }
    return out;
  }

  static normalName(ecosystem, name) {
    const text = String(name || "");
    return String(ecosystem).toLowerCase() === "pypi" ? text.toLowerCase().replace(/[-_.]+/g, "-") : text;
  }

  // OSV range semantics: sorted events; introduced opens, fixed closes (exclusive),
  // last_affected closes (inclusive). "0" means from the first version.
  static inRanges(ranges, ecosystem, version) {
    for (const range of ranges) {
      if (!["SEMVER", "ECOSYSTEM"].includes(range.type)) continue;
      const events = [...(range.events || [])].sort((a, b) => OsvMatch.compareEvent(ecosystem, a, b));
      let affected = false;
      for (const event of events) {
        if (event.introduced !== undefined) {
          if (event.introduced === "0" || Versions.compare(ecosystem, version, event.introduced) >= 0) affected = true;
        } else if (event.fixed !== undefined) {
          if (Versions.compare(ecosystem, version, event.fixed) >= 0) affected = false;
        } else if (event.last_affected !== undefined) {
          if (Versions.compare(ecosystem, version, event.last_affected) > 0) affected = false;
        }
      }
      if (affected) return true;
    }
    return false;
  }

  static eventVersion(event) {
    return event.introduced ?? event.fixed ?? event.last_affected ?? "0";
  }

  static compareEvent(ecosystem, a, b) {
    const x = OsvMatch.eventVersion(a);
    const y = OsvMatch.eventVersion(b);
    if (x === "0" && y !== "0") return -1;
    if (y === "0" && x !== "0") return 1;
    const c = Versions.compare(ecosystem, x, y);
    if (c !== 0) return c;
    // At the same version an introduced event comes first.
    return (a.introduced !== undefined ? 0 : 1) - (b.introduced !== undefined ? 0 : 1);
  }

  // Fixed versions named by the record for this package, sorted ascending.
  static fixedVersions(record, ecosystem, name) {
    const out = new Set();
    for (const entry of record.affected || []) {
      const pkg = entry.package || {};
      if (OsvMatch.normalName(ecosystem, pkg.name) !== OsvMatch.normalName(ecosystem, name)) continue;
      for (const range of entry.ranges || []) {
        if (!["SEMVER", "ECOSYSTEM"].includes(range.type)) continue;
        for (const event of range.events || []) if (event.fixed) out.add(event.fixed);
      }
    }
    return [...out].sort((a, b) => Versions.compare(ecosystem, a, b));
  }

  // Severity: the record's CVSS vector and, when given, database_specific.severity text.
  static severity(record) {
    const vector = (record.severity || []).find(s => /^CVSS_V[34]/.test(s.type))?.score || null;
    let label = record.database_specific?.severity ? String(record.database_specific.severity).toUpperCase() : null;
    if (label === "MODERATE") label = "MEDIUM";
    return { vector, label, score: vector ? Cvss.baseScore(vector) : null };
  }
}

// CVSS v3.x base score from a vector string (FIRST specification, section 7).
export class Cvss {
  static W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    C: { H: 0.56, L: 0.22, N: 0 },
  };

  static roundUp(x) {
    const i = Math.round(x * 100000);
    return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
  }

  static baseScore(vector) {
    const m = /^CVSS:3\.[01]\/(.*)$/.exec(String(vector || ""));
    if (!m) return null;
    const v = Object.fromEntries(m[1].split("/").map(p => p.split(":")));
    const changed = v.S === "C";
    const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[v.PR];
    const c = Cvss.W.C[v.C];
    const i = Cvss.W.C[v.I];
    const a = Cvss.W.C[v.A];
    if ([Cvss.W.AV[v.AV], Cvss.W.AC[v.AC], pr, Cvss.W.UI[v.UI], c, i, a].some(x => x === undefined)) return null;
    const iss = 1 - (1 - c) * (1 - i) * (1 - a);
    const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const exploitability = 8.22 * Cvss.W.AV[v.AV] * Cvss.W.AC[v.AC] * pr * Cvss.W.UI[v.UI];
    if (impact <= 0) return 0;
    return changed ? Cvss.roundUp(Math.min(1.08 * (impact + exploitability), 10)) : Cvss.roundUp(Math.min(impact + exploitability, 10));
  }

  static rating(score) {
    if (score === null || score === undefined) return null;
    if (score === 0) return "NONE";
    if (score < 4) return "LOW";
    if (score < 7) return "MEDIUM";
    if (score < 9) return "HIGH";
    return "CRITICAL";
  }
}
