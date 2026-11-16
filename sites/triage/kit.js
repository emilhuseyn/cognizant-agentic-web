// Browser Desk Kit: validate a desk.json and download a ready-to-host maintainer desk as a zip.
// Uses the same core as the CLI (kit/desk-kit.js) and this site's own copy of the runtime to parse
// and validate the network, so the zip holds what the runtime will load.
import { DeskKit, TEMPLATE_FILES } from "./kit/desk-kit.js";
import { parseHocon } from "./runtime/hocon.js";
import { AgentNetwork, validateNetwork } from "./runtime/kernel.js";
import { Zip } from "./kit/zip.js";

const $ = s => document.querySelector(s);
const base = new URL("./", import.meta.url);

async function text(rel) {
  const r = await fetch(new URL(rel, base));
  if (!r.ok) throw new Error(`${rel}: HTTP ${r.status}`);
  return r.text();
}

async function bytes(rel) {
  const r = await fetch(new URL(rel, base));
  if (!r.ok) throw new Error(`${rel}: HTTP ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

function readDesk() {
  try {
    return { desk: JSON.parse($("#desk-json").value) };
  } catch (error) {
    return { error: `desk.json is not valid JSON: ${error.message}` };
  }
}

function show(kind, lines) {
  const box = $("#kit-result");
  box.className = `result ${kind}`;
  box.textContent = "";
  for (const line of [].concat(lines)) {
    const p = document.createElement("p");
    p.textContent = line;
    box.append(p);
  }
}

function validate() {
  const { desk, error } = readDesk();
  if (error) { show("error", error); return null; }
  const errors = DeskKit.validate(desk);
  let url;
  try {
    url = new URL($("#desk-url").value.trim());
    if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) errors.push("Desk URL: use https (http only for localhost).");
  } catch {
    errors.push("Desk URL: the address where you will host the desk, such as https://security.myproject.org/.");
  }
  if (errors.length) { show("error", errors); return null; }
  return { desk, baseUrl: url.href };
}

async function build() {
  const ok = validate();
  if (!ok) return;
  show("warn", "Building…");
  try {
    const kit = new DeskKit(ok.desk, { out: null, baseUrl: ok.baseUrl });
    const [files, baseCss, deskCss, assistantCss, bridgeHtml] = await Promise.all([
      fetch(new URL("kit/files.json", base)).then(r => r.json()),
      text("kit/template/base.css"), text("kit/template/desk.css"), text("kit/template/assistant.css"), text("kit/template/action-bridge.html"),
    ]);
    const generated = kit.generatedFiles({
      runtime: { parseHocon, AgentNetwork, validateNetwork },
      bridgeHtml,
      css: DeskKit.composeCss(baseCss, deskCss, assistantCss, ok.desk.theme),
    });
    const enc = new TextEncoder();
    const entries = [];
    for (const [name, body] of Object.entries(generated)) entries.push({ name, data: enc.encode(body) });
    for (const rel of files.runtime) entries.push({ name: rel, data: await bytes(rel) });
    for (const f of TEMPLATE_FILES) entries.push({ name: f, data: await bytes(`kit/template/${f}`) });
    entries.push({ name: "osv-match.js", data: await bytes("osv-match.js") });
    entries.push({ name: "site.js", data: await bytes("site.js") });
    entries.push({ name: "desk.json", data: enc.encode(JSON.stringify(ok.desk, null, 2) + "\n") });
    const zip = Zip.build(entries);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(zip);
    a.download = `${ok.desk.project}-security-desk.zip`;
    document.body.append(a);
    a.click();
    a.remove();
    show("ok", [
      `Built ${entries.length} files (${Math.round(zip.size / 1024)} KB): ${ok.desk.project}-security-desk.zip.`,
      `Unzip it at the root of ${ok.baseUrl} on any static host with HTTPS. _headers and vercel.json set the CORS header the spec asks for.`,
      `Your network URL will be ${new URL(ok.desk.network, ok.baseUrl).href}. Other agentic websites put that URL in their agent's tools.`,
    ]);
  } catch (error) {
    show("error", `Build failed: ${error.message}`);
  }
}

async function loadExample() {
  $("#desk-json").value = await text("kit/example-desk.json");
  $("#desk-url").value = "https://security.lanternmd.example/";
  show("ok", "Example loaded: the fictional lanternmd desk. Edit it, or paste your own.");
}

$("#kit-validate").addEventListener("click", () => { if (validate()) show("ok", "desk.json is valid."); });
$("#kit-build").addEventListener("click", build);
$("#kit-example").addEventListener("click", loadExample);
loadExample();
