#!/usr/bin/env node
// Build every site for one environment.
//
//   node scripts/build_all.mjs [--env local|prod] [--check]
//
// Desks: desks/<name>/desk.json -> sites/<name>-desk/ through the Desk Kit.
// Triage Desk: src/triage/ -> sites/triage/, with the desk directory, partner tools, link labels
// and allowed_peers filled in from config/environments.json.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DeskKit, DeskKitWriter } from "../kit/build_desk.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SKILL = path.join(ROOT, "tools", "agentify-website");
const MARKER = ".built-by-build-all";
const ROUTER = "https://api.otari.ai/api/v1";

function safeName(s) {
  return s.replace(/[^A-Za-z0-9_]/g, "_").replace(/^_+/, "").slice(0, 60) || "tool";
}

function runBuild(hocon, manifest, check) {
  const args = [path.join(SKILL, "scripts", "build_network.mjs"), hocon, "--manifest", manifest];
  if (check) args.push("--check");
  const result = spawnSync(process.execPath, args, { encoding: "utf8" });
  const lines = (result.stdout + result.stderr).split("\n").filter(l => /^(WARNING|ERROR|OK|Network|Agents|  - [a-z_]+: \d+)/.test(l));
  return { ok: result.status === 0, text: lines.join("\n"), full: result.stdout + result.stderr };
}

async function clearBuilt(dir) {
  if (existsSync(dir)) {
    const entries = await readdir(dir);
    if (entries.length && !entries.includes(MARKER) && !entries.includes(".desk-kit")) throw new Error(`${dir} is not a build output folder.`);
    for (const entry of entries) await rm(path.join(dir, entry), { recursive: true, force: true });
  }
  await mkdir(dir, { recursive: true });
}

async function buildDesks(env, check) {
  const directory = [];
  for (const name of Object.keys(env.desks)) {
    const desk = JSON.parse(await readFile(path.join(ROOT, "desks", name, "desk.json"), "utf8"));
    const errors = DeskKit.validate(desk);
    if (errors.length) throw new Error(`desks/${name}/desk.json: ${errors.join(" ")}`);
    const base = env.desks[name];
    const kit = new DeskKitWriter(desk, { out: path.join(ROOT, "sites", `${name}-desk`), baseUrl: base });
    await kit.write();
    const r = runBuild(path.join(kit.out, `${desk.network}.hocon`), path.join(kit.out, "agent-manifest.json"), false);
    console.log(`\n[${name} desk] ${r.text}`);
    if (!r.ok) throw new Error(`${name} desk build failed:\n${r.full}`);
    if (check) {
      const c = runBuild(path.join(kit.out, `${desk.network}.hocon`), path.join(kit.out, "agent-manifest.json"), true);
      if (!c.ok) throw new Error(`${name} desk check failed:\n${c.full}`);
    }
    const networkUrl = new URL(desk.network, base).href;
    directory.push({
      project: desk.project,
      ecosystem: desk.ecosystem,
      label: `${desk.project} maintainers`,
      network: desk.network,
      networkUrl,
      tool: safeName(new URL(networkUrl).pathname),
      pageUrl: base,
      feedUrl: new URL("osv/index.json", base).href,
      fictional: Boolean(desk.fictional),
    });
  }
  return directory;
}

function triageManifest(directory, sampleQueries) {
  const network = "triage_desk";
  return {
    brand: "Triage Desk",
    networks: [{
      name: network,
      front_man: network,
      hocon: `./${network}.network.json`,
      description: "Triage the vulnerability findings in a dependency list, asking the maintainers' own security desks, and record OpenVEX decisions.",
      tags: ["agentified-website", "vulnerability-triage", "openvex", "osv", "maintainer-desk"],
      sample_queries: sampleQueries,
    }],
    llm_router: { base_url: ROUTER, mock: false, byok_router: ROUTER },
    allowed_peers: [...new Set(directory.map(d => new URL(d.networkUrl).origin))],
    peer_policy: {
      mode: "closed",
      deny_origins: [],
      note: "Calls the maintainer desks in allowed_peers, each only after the visitor agrees on a consent card. Requests carry a package, a version, an advisory id and a usage question; never names, emails or code.",
    },
    agent_mcp: {
      protocol: "nsdeploy-agent-mcp/v1",
      network,
      front_man: network,
      available: false,
      reason: "This is a static bundle; a public MCP facade requires an application host.",
    },
    theme: { primary: "#1f4f99" },
    linking: {
      protocol: "nsdeploy-link/v1",
      exports: [{ network, front_man: network, aliases: [network], url: network }],
      imports: [],
      link_updates: { mode: "browser-local" },
    },
    deployment: { mode: "static", self_contained_runtime: true, browser_mock: false, direct_byok: true, direct_mcp_requires_cors: true, public_mcp_facade: false },
    actions: { version: 1, module: "./site-actions.js", bridge: "./bridge/action-bridge.html", agentTools: ["get_findings", "get_advisory", "propose_vex_statement"] },
  };
}

async function buildTriage(env, directory, check) {
  const src = path.join(ROOT, "src", "triage");
  const out = path.join(ROOT, "sites", "triage");
  await clearBuilt(out);
  await writeFile(path.join(out, MARKER), "Made by scripts/build_all.mjs from src/triage. Edit the source, not this folder.\n");
  for (const entry of await readdir(src)) {
    if (entry.endsWith(".in") || entry === "triage.css") continue;
    await cp(path.join(src, entry), path.join(out, entry), { recursive: true });
  }
  await cp(path.join(SKILL, "runtime"), path.join(out, "runtime"), { recursive: true });
  await cp(path.join(ROOT, "shared", "osv-match.js"), path.join(out, "osv-match.js"));
  await cp(path.join(ROOT, "shared", "site.js"), path.join(out, "site.js"));
  // The browser Desk Kit (kit.html): the kit core, its templates, an example desk and the list of
  // runtime files it zips. desk-kit.js imports ../shared/osv-match.js, so that path exists too.
  for (const entry of await readdir(path.join(ROOT, "kit", "web"))) await cp(path.join(ROOT, "kit", "web", entry), path.join(out, entry));
  await mkdir(path.join(out, "kit", "template"), { recursive: true });
  await mkdir(path.join(out, "shared"), { recursive: true });
  await cp(path.join(ROOT, "kit", "desk-kit.js"), path.join(out, "kit", "desk-kit.js"));
  await cp(path.join(ROOT, "kit", "zip.js"), path.join(out, "kit", "zip.js"));
  await cp(path.join(ROOT, "shared", "osv-match.js"), path.join(out, "shared", "osv-match.js"));
  await cp(path.join(ROOT, "desks", "lanternmd", "desk.json"), path.join(out, "kit", "example-desk.json"));
  for (const f of ["desk-page.js", "site-actions.js", "desk.css"]) await cp(path.join(ROOT, "kit", "template", f), path.join(out, "kit", "template", f));
  await cp(path.join(ROOT, "shared", "base.css"), path.join(out, "kit", "template", "base.css"));
  await cp(path.join(SKILL, "templates", "assistant.css"), path.join(out, "kit", "template", "assistant.css"));
  await cp(path.join(SKILL, "templates", "bridge", "action-bridge.html"), path.join(out, "kit", "template", "action-bridge.html"));
  const runtimeFiles = [];
  const walk = async (dir, rel) => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (e.isDirectory()) await walk(path.join(dir, e.name), `${rel}${e.name}/`);
      else runtimeFiles.push(`${rel}${e.name}`);
    }
  };
  await walk(path.join(SKILL, "runtime"), "runtime/");
  await writeFile(path.join(out, "kit", "files.json"), JSON.stringify({ runtime: runtimeFiles.sort() }, null, 2) + "\n");
  const css = [
    await readFile(path.join(ROOT, "shared", "base.css"), "utf8"),
    await readFile(path.join(src, "triage.css"), "utf8"),
    await readFile(path.join(SKILL, "templates", "assistant.css"), "utf8")
      .then(t => t.replace("--ns-primary: #2563eb;", "--ns-primary: #1f4f99;").replace("--ns-accent: #2563eb;", "--ns-accent: #1f4f99;")),
  ].join("\n");
  await writeFile(path.join(out, "styles.css"), css);
  await writeFile(path.join(out, "desks.json"), JSON.stringify(directory, null, 2) + "\n");

  let hocon = await readFile(path.join(src, "triage_desk.hocon.in"), "utf8");
  const labels = directory.map(d => `        ${JSON.stringify(d.networkUrl)}: ${JSON.stringify(d.label)}`).join(",\n");
  const lines = directory.map(d => `- For ${d.project} (${d.ecosystem}) findings, ask ${d.tool}, the ${d.project} maintainers' security desk.`).join("\n");
  const tools = JSON.stringify([...directory.map(d => d.networkUrl), "vex_analyst"]);
  hocon = hocon.replace("@@LINK_LABELS@@", labels).replace("@@DESK_LINES@@", lines).replace("@@DESK_TOOLS@@", tools)
    .replace(/^# Triage Desk assistant\.[\s\S]*?triage_desk\.network\.json\.\n/, "# Triage Desk assistant. Generated by scripts/build_all.mjs from src/triage/triage_desk.hocon.in;\n# this file is the source of truth for triage_desk.network.json.\n");
  if (/@@[A-Z_]+@@/.test(hocon)) throw new Error("triage_desk.hocon still has a @@ marker.");
  await writeFile(path.join(out, "triage_desk.hocon"), hocon);

  const sample = JSON.parse(hocon.replace(/^\s*#.*$/gm, "").match(/"sample_queries":\s*(\[[\s\S]*?\])/)[1]);
  await writeFile(path.join(out, "agent-manifest.json"), JSON.stringify(triageManifest(directory, sample), null, 2) + "\n");
  await writeFile(path.join(out, "links.json"), JSON.stringify({ version: 1, networks: { triage_desk: {} } }, null, 2) + "\n");
  await writeFile(path.join(out, ".nojekyll"), "");
  const cors = ["/agent-manifest.json", "/triage_desk.network.json", "/triage_desk.hocon", "/links.json", "/agent-mcp.json", "/desks.json", "/.well-known/nsdeploy.json", "/.well-known/nsdeploy-agent.json"];
  await writeFile(path.join(out, "_headers"), cors.map(p => `${p}\n  Access-Control-Allow-Origin: *\n`).join("") +
    "/runtime/sandbox-worker.js\n  Content-Security-Policy: default-src 'none'; script-src blob:; connect-src 'none'; worker-src 'none'\n/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n");

  const r = runBuild(path.join(out, "triage_desk.hocon"), path.join(out, "agent-manifest.json"), false);
  console.log(`\n[triage] ${r.text}`);
  if (!r.ok) throw new Error(`triage build failed:\n${r.full}`);
  if (check) {
    const c = runBuild(path.join(out, "triage_desk.hocon"), path.join(out, "agent-manifest.json"), true);
    if (!c.ok) throw new Error(`triage check failed:\n${c.full}`);
  }
}

async function main(argv) {
  const envName = argv.includes("--env") ? argv[argv.indexOf("--env") + 1] : "local";
  const check = argv.includes("--check");
  const envs = JSON.parse(await readFile(path.join(ROOT, "config", "environments.json"), "utf8"));
  const env = envs[envName];
  if (!env) throw new Error(`No environment "${envName}" in config/environments.json.`);
  if (Object.values(env.desks).some(u => u.includes("TO-BE-DECIDED"))) throw new Error(`Environment "${envName}" has desk URLs that are not decided yet.`);
  const directory = await buildDesks(env, check);
  await buildTriage(env, directory, check);
  console.log(`\nBuilt for ${envName}: triage ${env.triage}, desks ${Object.values(env.desks).join(", ")}`);
}

await main(process.argv.slice(2));
