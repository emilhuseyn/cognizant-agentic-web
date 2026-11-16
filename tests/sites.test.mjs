// Triage flow with a fake network, the Desk Kit's validation, and the spec build checks on every built
// site. Run after `node scripts/build_all.mjs --env local`.
import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DeskKit } from "../kit/build_desk.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const json = async rel => JSON.parse(await readFile(path.join(ROOT, rel), "utf8"));

// A fake fetch: OSV answers from fixtures, desk feeds from the built desk folders.
async function fakeFetch(desks) {
  const lodashGhsa = {
    id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], summary: "Command Injection in lodash",
    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
    affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
  };
  const lodashDup = { id: "PYSEC-FAKE-1", aliases: ["GHSA-35jh-r3h4-6jhm"], summary: "same issue, other database", affected: lodashGhsa.affected };
  const calls = [];
  const fetcher = async (url, init) => {
    const u = String(url);
    calls.push({ url: u, body: init?.body || null });
    const ok = body => ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) });
    if (u.endsWith("/v1/querybatch")) {
      const q = JSON.parse(init.body).queries;
      return ok({ results: q.map(x => (x.package.name === "lodash" ? { vulns: [{ id: lodashGhsa.id }, { id: lodashDup.id }] } : {})) });
    }
    if (u.includes("/v1/vulns/")) return ok(u.endsWith(lodashGhsa.id) ? lodashGhsa : lodashDup);
    for (const d of desks) {
      if (u.startsWith(d.pageUrl)) {
        const rel = u.slice(d.pageUrl.length);
        return ok(await json(`sites/${d.project}-desk/${rel}`));
      }
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  return { fetcher, calls };
}

test("triage: OSV + desk feed findings, alias merge, privacy of the OSV query", async () => {
  const desks = await json("sites/triage/desks.json");
  const { TriagePage } = await import("../sites/triage/js/triage-page.js");
  const { fetcher, calls } = await fakeFetch(desks);
  const page = new TriagePage(desks, fetcher);
  page.setInput({ appName: "demo (demo app)", npmText: JSON.stringify({ dependencies: { lodash: "4.17.15", lanternmd: "3.0.2" } }), pypiText: "tidecache==2.0.1\n" });
  const r = await page.runCheck();
  assert.equal(r.ok, true);
  const ids = page.findings.map(f => f.advisoryId).sort();
  assert.deepEqual(ids, ["GHSA-35jh-r3h4-6jhm", "LANTERN-2026-0001", "LANTERN-2026-0002", "LANTERN-2026-0003", "TIDE-2026-0002"]);
  const lodash = page.findings.find(f => f.package === "lodash");
  assert.ok(lodash.aliases.includes("PYSEC-FAKE-1"), "the duplicate record becomes an alias");
  // Only package names and versions go to OSV.dev; desk packages are not sent there.
  const batch = JSON.parse(calls.find(c => c.url.endsWith("/querybatch")).body);
  assert.deepEqual(batch.queries, [{ package: { name: "lodash", ecosystem: "npm" }, version: "4.17.15" }]);
  const view = page.getFindings();
  assert.equal(view.findings.find(f => f.advisoryId === "LANTERN-2026-0001").desk.askTool, "lanternmd_security_desk");
  assert.ok(JSON.stringify(view).length < 4000, "the findings view stays small");
});

test("triage: proposals are staged, the desk citation needs a contact, VEX export", async () => {
  const desks = await json("sites/triage/desks.json");
  const { TriagePage } = await import("../sites/triage/js/triage-page.js");
  const { fetcher } = await fakeFetch(desks);
  const page = new TriagePage(desks, fetcher);
  page.setInput({ appName: "demo (demo app)", npmText: JSON.stringify({ dependencies: { lanternmd: "3.0.2" } }), pypiText: "" });
  await page.runCheck();
  const key = page.findings.find(f => f.advisoryId === "LANTERN-2026-0001").key;
  const cite = { findingKey: key, status: "not_affected", justification: "vulnerable_code_not_in_execute_path", evidence: [{ source: "maintainer desk", text: "html off" }] };
  assert.match(page.proposeStatement(cite).reason, /not asked in this session/);
  page.notePeerConsent({ kind: "network", peerLabel: "lanternmd maintainers", peerOrigin: new URL(desks[0].networkUrl).host, requestText: "q" }, "decline");
  assert.equal(page.proposeStatement(cite).ok, false, "a declined card is not a contact");
  page.notePeerConsent({ kind: "network", peerLabel: "lanternmd maintainers", peerOrigin: new URL(desks[0].networkUrl).host, requestText: "q" }, "allow");
  const p = page.proposeStatement(cite);
  assert.equal(p.ok, true);
  assert.equal(p.recorded, false);
  assert.equal(page.decisions.size, 0, "nothing is recorded until the visitor applies it");
  page.applyProposal(p.proposalId);
  const doc = await page.exportVex("Tester");
  assert.equal(doc.statements.length, 1);
  assert.equal(doc.statements[0].products[0]["@id"], "pkg:generic/demo");
  assert.equal(doc.statements[0].status_notes, `lanternmd maintainers (${new URL(desks[0].networkUrl).host}): html off`);
});

test("kit: validation catches broken desk files", async () => {
  const good = await json("desks/lanternmd/desk.json");
  assert.deepEqual(DeskKit.validate(good), []);
  const bad = structuredClone(good);
  bad.network = "Bad-Name";
  bad.report.email = "nobody";
  bad.advisories[0].affected[0].package.name = "other";
  delete bad.advisories[1].database_specific.desk.notAffectedWhen;
  bad.advisories[2].id = bad.advisories[0].id;
  const errors = DeskKit.validate(bad).join("\n");
  for (const want of ["network:", "report.email", "must name npm/lanternmd", "notAffectedWhen", "duplicate id"]) assert.ok(errors.includes(want), want);
});

test("kit: the desk network carries the maintainers' notes for remote callers", async () => {
  const hocon = await readFile(path.join(ROOT, "sites/lanternmd-desk/lanternmd_security_desk.hocon"), "utf8");
  for (const id of ["LANTERN-2026-0001", "LANTERN-2026-0002", "LANTERN-2026-0003"]) assert.ok(hocon.includes(id), id);
  assert.match(hocon, /still ask advisory_notes/);
  const net = await json("sites/lanternmd-desk/lanternmd_security_desk.network.json");
  const notes = net.tools.find(t => t.name === "advisory_notes");
  assert.match(notes.instructions, /Affected versions: >=2\.0\.0 <2\.4\.1; >=3\.0\.0 <3\.1\.2/);
});

for (const [site, network] of [["triage", "triage_desk"], ["lanternmd-desk", "lanternmd_security_desk"], ["tidecache-desk", "tidecache_security_desk"]]) {
  test(`spec build check passes: ${site}`, () => {
    const dir = path.join(ROOT, "sites", site);
    const r = spawnSync(process.execPath, [path.join(ROOT, "tools/agentify-website/scripts/build_network.mjs"), path.join(dir, `${network}.hocon`), "--manifest", path.join(dir, "agent-manifest.json"), "--check"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.doesNotMatch(r.stdout, /^ERROR/m);
  });

  test(`published files: ${site}`, async () => {
    const m = await json(`sites/${site}/agent-manifest.json`);
    assert.equal(m.networks[0].name, network);
    assert.equal(m.peer_policy.mode, "closed");
    assert.equal(m.deployment.mode, "static");
    assert.equal(m.actions.bridge, "./bridge/action-bridge.html");
    const links = await json(`sites/${site}/links.json`);
    assert.equal(links.version, 1);
    const text = await readFile(path.join(ROOT, "sites", site, `${network}.network.json`), "utf8");
    assert.doesNotMatch(text, /otk_[A-Za-z0-9]{8}|sk-[A-Za-z0-9]{20}|demo_mode/);
  });
}

test("browser kit zip: a valid archive with the desk's files (checked by Python's zipfile)", async () => {
  const { Zip } = await import("../kit/zip.js");
  const enc = new TextEncoder();
  const entries = [
    { name: "index.html", data: enc.encode("<!doctype html><p>ok</p>\n") },
    { name: ".well-known/nsdeploy.json", data: enc.encode("{}\n") },
    { name: "osv/LANTERN-2026-0001.json", data: await readFile(path.join(ROOT, "sites/lanternmd-desk/osv/LANTERN-2026-0001.json")) },
  ];
  const blob = Zip.build(entries);
  const { writeFile, mkdtemp } = await import("node:fs/promises");
  const os = await import("node:os");
  const dir = await mkdtemp(path.join(os.tmpdir(), "deskzip-"));
  const file = path.join(dir, "desk.zip");
  await writeFile(file, Buffer.from(await blob.arrayBuffer()));
  const r = spawnSync("py", ["-I", "-c", "import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);assert z.testzip() is None;print(chr(10).join(z.namelist()))", file], { encoding: "utf8" });
  if (r.error && r.error.code === "ENOENT") return; // no Python on this machine
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.stdout.trim().split(/\r?\n/), entries.map(e => e.name));
});
