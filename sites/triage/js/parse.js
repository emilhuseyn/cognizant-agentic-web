// Dependency list parsers: package.json, package-lock.json (v1, v2, v3) and requirements.txt.
// Each returns {dependencies: [{name, ecosystem, version, declared, pinned, direct, note}], warnings}.

const SEMVER_EXACT = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const RANGE_BASE = /^(?:[\^~]|>=|=|v)?\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;

export class DependencyParser {
  static MAX = 500;

  static parseNpm(text) {
    const trimmed = String(text || "").trim();
    if (!trimmed) return { dependencies: [], warnings: [] };
    let json;
    try {
      json = JSON.parse(trimmed);
    } catch (error) {
      return { dependencies: [], warnings: [`The npm box is not valid JSON: ${error.message}`] };
    }
    if (json && typeof json === "object" && (json.lockfileVersion || json.packages)) return DependencyParser.parseLock(json);
    return DependencyParser.parsePackageJson(json);
  }

  static parsePackageJson(json) {
    const out = [];
    const warnings = [];
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      for (const [name, spec] of Object.entries(json?.[field] || {})) {
        const declared = String(spec).trim();
        if (SEMVER_EXACT.test(declared)) {
          out.push({ name, ecosystem: "npm", version: declared, declared, pinned: true, direct: true, dev: field === "devDependencies", note: "" });
          continue;
        }
        const m = RANGE_BASE.exec(declared);
        if (m) {
          out.push({ name, ecosystem: "npm", version: m[1], declared, pinned: false, direct: true, dev: field === "devDependencies", note: `Range ${declared}: checked ${m[1]}, the lowest version it allows. Paste package-lock.json for the installed version.` });
        } else {
          warnings.push(`${name} ${declared}: not a version or a simple range, so it was skipped. Paste package-lock.json to check it.`);
        }
      }
    }
    return { dependencies: out, warnings };
  }

  static lockName(key) {
    const idx = key.lastIndexOf("node_modules/");
    return idx === -1 ? null : key.slice(idx + "node_modules/".length);
  }

  static parseLock(json) {
    const out = [];
    const warnings = [];
    const seen = new Set();
    const rootDeps = new Set(Object.keys({ ...(json.packages?.[""]?.dependencies || {}), ...(json.packages?.[""]?.devDependencies || {}), ...(json.dependencies && !json.packages ? json.dependencies : {}) }));
    const add = (name, version, direct, dev) => {
      if (!name || !version || !SEMVER_EXACT.test(version)) return;
      const key = `${name}@${version}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ name, ecosystem: "npm", version, declared: version, pinned: true, direct, dev: Boolean(dev), note: direct ? "" : "transitive" });
    };
    if (json.packages) {
      for (const [key, entry] of Object.entries(json.packages)) {
        if (!key || entry.link) continue;
        const name = entry.name || DependencyParser.lockName(key);
        add(name, entry.version, key === `node_modules/${name}` && rootDeps.has(name), entry.dev);
      }
    } else if (json.dependencies) {
      const walk = (deps, depth) => {
        for (const [name, entry] of Object.entries(deps || {})) {
          add(name, entry.version, depth === 0, entry.dev);
          if (entry.dependencies) walk(entry.dependencies, depth + 1);
        }
      };
      walk(json.dependencies, 0);
    }
    if (out.length > DependencyParser.MAX) {
      warnings.push(`The lockfile lists ${out.length} packages; the first ${DependencyParser.MAX} are checked.`);
      out.length = DependencyParser.MAX;
    }
    return { dependencies: out, warnings };
  }

  static parseRequirements(text) {
    const out = [];
    const warnings = [];
    for (const raw of String(text || "").split(/\r?\n/)) {
      const line = raw.replace(/\s+#.*$/, "").replace(/^#.*$/, "").trim();
      if (!line) continue;
      if (line.startsWith("-") || line.includes("://")) {
        warnings.push(`"${line}": options, includes and URLs are skipped.`);
        continue;
      }
      const spec = line.split(";")[0].trim();
      const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===?|>=|~=|<=|!=|>|<)?\s*([^,\s]*)?/.exec(spec);
      if (!m) {
        warnings.push(`"${line}": not understood, skipped.`);
        continue;
      }
      const [, name, , op, version] = m;
      if ((op === "==" || op === "===") && version && !version.includes("*")) {
        out.push({ name, ecosystem: "PyPI", version, declared: spec, pinned: true, direct: true, dev: false, note: "" });
      } else {
        warnings.push(`${name}: not pinned with ==, so its installed version is unknown. Run pip freeze and paste that.`);
      }
    }
    return { dependencies: out, warnings };
  }
}
