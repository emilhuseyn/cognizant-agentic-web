// Unit tests for the shared logic. Run after `node scripts/build_all.mjs` (the triage page is tested
// from its built copy, which has osv-match.js next to it).
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { Cvss, OsvMatch, Versions } from "../shared/osv-match.js";
import { DependencyParser } from "../src/triage/js/parse.js";
import { Vex } from "../src/triage/js/vex.js";

const range = (...events) => ({ affected: [{ package: { ecosystem: "npm", name: "p" }, ranges: [{ type: "SEMVER", events }] }] });

test("semver order, including pre-releases", () => {
  assert.equal(Versions.compareSemver("3.0.10", "3.0.9"), 1);
  assert.equal(Versions.compareSemver("1.0.0-rc.1", "1.0.0"), -1);
  assert.equal(Versions.compareSemver("1.0.0-alpha", "1.0.0-alpha.1"), -1);
  assert.equal(Versions.compareSemver("1.0.0-alpha.beta", "1.0.0-beta"), -1);
  assert.equal(Versions.compareSemver("2.0.0", "2.0.0"), 0);
});

test("PEP 440 order", () => {
  const ordered = ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0.post1", "1.0.1", "1.1"];
  for (let i = 1; i < ordered.length; i++) assert.equal(Versions.comparePep440(ordered[i - 1], ordered[i]), -1, `${ordered[i - 1]} < ${ordered[i]}`);
  assert.equal(Versions.comparePep440("2.0", "2.0.0"), 0);
});

test("OSV ranges: introduced, fixed, several windows, last_affected", () => {
  const r = range({ introduced: "2.0.0" }, { fixed: "2.4.1" }, { introduced: "3.0.0" }, { fixed: "3.1.2" });
  const hit = v => OsvMatch.affects(r, "npm", "p", v);
  assert.equal(hit("1.9.9"), false);
  assert.equal(hit("2.0.0"), true);
  assert.equal(hit("2.4.1"), false);
  assert.equal(hit("2.9.0"), false);
  assert.equal(hit("3.0.2"), true);
  assert.equal(hit("3.1.2"), false);
  const zero = range({ introduced: "0" }, { fixed: "1.2.6" });
  assert.equal(OsvMatch.affects(zero, "npm", "p", "1.2.5"), true);
  const last = range({ introduced: "1.0.0" }, { last_affected: "1.4.0" });
  assert.equal(OsvMatch.affects(last, "npm", "p", "1.4.0"), true);
  assert.equal(OsvMatch.affects(last, "npm", "p", "1.4.1"), false);
  assert.equal(OsvMatch.affects(r, "npm", "other", "3.0.2"), false);
});

test("fixed versions skip GIT ranges; PyPI names normalise", () => {
  const rec = { affected: [{ package: { ecosystem: "PyPI", name: "Tide_Cache" }, ranges: [
    { type: "GIT", events: [{ introduced: "0" }, { fixed: "74ea7cf7" }] },
    { type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.8.0" }] }] }] };
  assert.deepEqual(OsvMatch.fixedVersions(rec, "PyPI", "tide-cache"), ["1.8.0"]);
  assert.equal(OsvMatch.affects(rec, "PyPI", "tide.cache", "1.7.9"), true);
});

test("CVSS 3.1 base scores match the FIRST calculator", () => {
  assert.equal(Cvss.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(Cvss.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
  assert.equal(Cvss.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"), 5.3);
  assert.equal(Cvss.baseScore("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"), 5.9);
  assert.equal(Cvss.baseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"), 9.1);
  assert.equal(Cvss.baseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), null);
  assert.equal(Cvss.rating(9.1), "CRITICAL");
  assert.equal(OsvMatch.severity({ database_specific: { severity: "MODERATE" } }).label, "MEDIUM");
});

test("package.json: exact versions, simple ranges, skipped specs", () => {
  const r = DependencyParser.parseNpm(JSON.stringify({ dependencies: { a: "1.2.3", b: "^4.17.15", c: "github:x/y" }, devDependencies: { d: "~2.0.1" } }));
  assert.deepEqual(r.dependencies.map(d => [d.name, d.version, d.pinned]), [["a", "1.2.3", true], ["b", "4.17.15", false], ["d", "2.0.1", false]]);
  assert.equal(r.warnings.length, 1);
  assert.match(DependencyParser.parseNpm("{not json").warnings[0], /not valid JSON/);
});

test("package-lock.json v3 and v1", () => {
  const v3 = { lockfileVersion: 3, packages: { "": { dependencies: { express: "^4" } }, "node_modules/express": { version: "4.17.1" }, "node_modules/express/node_modules/qs": { version: "6.7.0" }, "node_modules/@scope/x": { version: "1.0.0", dev: true } } };
  const r3 = DependencyParser.parseNpm(JSON.stringify(v3)).dependencies;
  assert.deepEqual(r3.map(d => `${d.name}@${d.version}:${d.direct}`), ["express@4.17.1:true", "qs@6.7.0:false", "@scope/x@1.0.0:false"]);
  const v1 = { lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } } } };
  assert.deepEqual(DependencyParser.parseNpm(JSON.stringify(v1)).dependencies.map(d => d.name), ["a", "b"]);
});

test("requirements.txt: only == pins are checked", () => {
  const r = DependencyParser.parseRequirements("# c\njinja2==2.11.2\nrequests[socks]==2.25.0 ; python_version>'3'\nflask>=2\n-r other.txt\n");
  assert.deepEqual(r.dependencies.map(d => `${d.name}==${d.version}`), ["jinja2==2.11.2", "requests==2.25.0"]);
  assert.equal(r.warnings.length, 2);
});

test("OpenVEX rules and document shape", async () => {
  assert.match(Vex.problem({ status: "not_affected" }), /justification/);
  assert.match(Vex.problem({ status: "affected" }), /action statement/);
  assert.match(Vex.problem({ status: "fixed", justification: "component_not_present" }), /only goes with not_affected/);
  assert.equal(Vex.problem({ status: "not_affected", justification: "inline_mitigations_already_exist" }), null);
  assert.equal(Vex.purl("PyPI", "Jinja_2", "2.11.2"), "pkg:pypi/jinja-2@2.11.2");
  assert.equal(Vex.purl("npm", "@scope/x", "1.0.0"), "pkg:npm/%40scope/x@1.0.0");
  const finding = { advisoryId: "GHSA-x", aliases: ["CVE-1"], ecosystem: "npm", package: "p", version: "1.0.0" };
  const s = Vex.statement(finding, { status: "affected", actionStatement: "Upgrade.", decidedAt: "t", evidence: [{ source: "visitor", text: "we parse input" }] }, "pkg:generic/app");
  const doc = await Vex.document({ author: "A", productId: "pkg:generic/app", statements: [s], timestamp: "2026-11-16T00:00:00Z" });
  assert.equal(doc["@context"], "https://openvex.dev/ns/v0.2.0");
  assert.match(doc["@id"], /^urn:uuid:[0-9a-f]{8}-/);
  assert.equal(doc.statements[0].action_statement, "Upgrade.");
  assert.equal(doc.statements[0].status_notes, "visitor: we parse input");
});

test("desk page: version check, support line, report draft (no DOM)", async () => {
  const { DeskPage } = await import("../sites/lanternmd-desk/desk-page.js");
  const data = JSON.parse(await readFile(new URL("../sites/lanternmd-desk/desk-data.json", import.meta.url), "utf8"));
  const page = new DeskPage(data);
  const r = page.checkVersion("3.0.2");
  assert.deepEqual(r.affectedBy.map(a => a.id), ["LANTERN-2026-0001", "LANTERN-2026-0002", "LANTERN-2026-0003"]);
  assert.match(r.supportLine, /^3\.x: supported/);
  assert.deepEqual(page.checkVersion("3.2.0").affectedBy.map(a => a.id), []);
  assert.deepEqual(page.checkVersion("2.4.1").affectedBy.map(a => a.id), ["LANTERN-2026-0002"]);
  assert.match(page.checkVersion("1.9.0").supportLine, /end of life/);
  assert.equal(page.checkVersion("three").ok, false);
  assert.equal(page.getAdvisory("NOPE").ok, false);
  assert.equal(page.draftReport({ summary: "" }).ok, false);
  const d = page.draftReport({ summary: "Crash on nested lists", affectedVersion: "3.2.0", details: "steps" });
  assert.equal(d.ok, true);
  assert.equal(d.sent, false);
  assert.match(page.reportMailto(), /^mailto:security@lanternmd\.example\?subject=/);
});

test("tidecache desk: PEP 440 ranges and 'and older' support line", async () => {
  const { DeskPage } = await import("../sites/tidecache-desk/desk-page.js");
  const data = JSON.parse(await readFile(new URL("../sites/tidecache-desk/desk-data.json", import.meta.url), "utf8"));
  const page = new DeskPage(data);
  assert.deepEqual(page.checkVersion("2.0.1").affectedBy.map(a => a.id), ["TIDE-2026-0002"]);
  assert.deepEqual(page.checkVersion("1.7.5").affectedBy.map(a => a.id), ["TIDE-2026-0001"]);
  assert.match(page.checkVersion("1.6.0").supportLine, /^1\.7\.x and older: end of life/);
  assert.match(page.checkVersion("1.8.2").supportLine, /^1\.8\.x: security fixes only/);
});
