#!/usr/bin/env node
// Desk Kit: turn a maintainer's desk.json (security policy + OSV advisories with applicability notes)
// into a complete, static, open agentic website that conforms to the Worldwide Agentic Web MVP spec.
//
// Usage:
//   node kit/build_desk.mjs <desk.json> --out <site folder> --base-url <https://desk.example/>
//
// The output folder holds the page, the browser runtime, the HOCON network and its resolved
// network JSON (built and validated by the runtime's own parser), agent-manifest.json, links.json,
// discovery files, the action bridge, an OSV feed, and header files for common static hosts.
// It refuses to write into a non-empty folder that it did not create.

import { spawnSync } from "node:child_process";
import { cp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DeskKit } from "./desk-kit.js";
import * as hocon from "../tools/agentify-website/runtime/hocon.js";
import * as kernel from "../tools/agentify-website/runtime/kernel.js";

const KIT = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(KIT, "..");
const SKILL = path.join(ROOT, "tools", "agentify-website");
const MARKER = ".desk-kit";

export { DeskKit };

// Writes a desk to disk and runs the sponsor's build_network.mjs check on it.
export class DeskKitWriter extends DeskKit {
  async prepareOut() {
    if (existsSync(this.out)) {
      const entries = await readdir(this.out);
      if (entries.length && !entries.includes(MARKER)) {
        throw new Error(`${this.out} is not empty and was not made by the kit. Pick an empty folder.`);
      }
      // Only a folder the kit made is cleared, file by file at the top level.
      for (const entry of entries) await rm(path.join(this.out, entry), { recursive: true, force: true });
    }
    await mkdir(this.out, { recursive: true });
  }

  async write() {
    await this.prepareOut();
    const out = this.out;
    await cp(path.join(SKILL, "runtime"), path.join(out, "runtime"), { recursive: true });
    for (const file of ["desk-page.js", "site-actions.js"]) await cp(path.join(KIT, "template", file), path.join(out, file));
    await cp(path.join(ROOT, "shared", "osv-match.js"), path.join(out, "osv-match.js"));
    await cp(path.join(ROOT, "shared", "site.js"), path.join(out, "site.js"));
    const css = DeskKit.composeCss(
      await readFile(path.join(ROOT, "shared", "base.css"), "utf8"),
      await readFile(path.join(KIT, "template", "desk.css"), "utf8"),
      await readFile(path.join(SKILL, "templates", "assistant.css"), "utf8"),
      this.desk.theme);
    const files = this.generatedFiles({
      runtime: { parseHocon: hocon.parseHocon, AgentNetwork: kernel.AgentNetwork, validateNetwork: kernel.validateNetwork },
      bridgeHtml: await readFile(path.join(SKILL, "templates", "bridge", "action-bridge.html"), "utf8"),
      css,
    });
    for (const [rel, text] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(out, rel)), { recursive: true });
      await writeFile(path.join(out, rel), text);
    }
    await writeFile(path.join(out, MARKER), "Made by kit/build_desk.mjs. The kit may clear and rewrite this folder.\n");
  }

  build(check = false) {
    const args = [path.join(SKILL, "scripts", "build_network.mjs"), path.join(this.out, `${this.desk.network}.hocon`), "--manifest", path.join(this.out, "agent-manifest.json")];
    if (check) args.push("--check");
    return spawnSync(process.execPath, args, { encoding: "utf8" });
  }
}

async function main(argv) {
  const args = {};
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out") args.out = argv[++i];
    else if (argv[i] === "--base-url") args.baseUrl = argv[++i];
    else rest.push(argv[i]);
  }
  if (rest.length !== 1 || !args.out || !args.baseUrl) {
    console.error("Usage: node kit/build_desk.mjs <desk.json> --out <site folder> --base-url <https://desk.example/>");
    return 2;
  }
  const desk = JSON.parse(await readFile(rest[0], "utf8"));
  const errors = DeskKit.validate(desk);
  if (errors.length) {
    for (const e of errors) console.error(`desk.json: ${e}`);
    return 1;
  }
  const kit = new DeskKitWriter(desk, { out: path.resolve(args.out), baseUrl: args.baseUrl });
  await kit.write();
  const result = kit.build(false);
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  if (result.status !== 0) return result.status || 1;
  console.log(`Desk written to ${kit.out}. Network URL: ${kit.baseUrl}${desk.network}`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
