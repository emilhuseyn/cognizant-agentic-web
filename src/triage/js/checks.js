// Spec section 6 checks, run in this browser with this site's own copy of the runtime. Each check calls
// the runtime code that enforces the rule and shows the runtime's own message. No model is needed and
// nothing is sent anywhere except this site's own fixture files.
import { Engine, selectPeerRouter } from "../runtime/engine.js";
import { AgentNetwork, allowedDownstreamSly, filterSlyData } from "../runtime/kernel.js";
import { fetchManifest } from "../runtime/remote.js";
import { consumeAgentBudget, consumeRemoteBudget } from "../runtime/runner.js";

const base = new URL("../", import.meta.url).href;

// The Triage Desk engine with its published manifest, as loadTop() sets it before compiling. The page
// actions are not loaded here: they belong to the main page.
async function topEngine() {
  const engine = new Engine({ originUrl: base });
  const { manifest, base: siteBase } = await fetchManifest(base);
  engine.top = { manifest, base: siteBase };
  return engine;
}

async function triageNetwork() {
  const config = await (await fetch(new URL("triage_desk.network.json", base))).json();
  return new AgentNetwork(config, "triage_desk");
}

function composition() {
  return { remoteCalls: 0, peerCalls: new Map(), maxRemoteCalls: 4, maxCallsPerPeer: 1, agentCalls: 0, maxAgentCalls: 24, deadline: Date.now() + 90_000 };
}

export const CHECKS = [
  {
    id: "invalid",
    title: "An invalid network is stopped before any model call",
    spec: "§3.1 Parse and validate; §6",
    async run() {
      const engine = new Engine({ originUrl: new URL("checks/invalid/", base).href });
      try {
        await engine.loadTop();
        return { pass: false, detail: "The runtime loaded the broken fixture." };
      } catch (error) {
        return { pass: true, detail: error.message };
      }
    },
  },
  {
    id: "denied",
    title: "An origin outside allowed_peers is refused before contact",
    spec: "§3.2 consent and per-hop policy; §5 fail closed; §6",
    async run() {
      const engine = await topEngine();
      try {
        await engine.resolveRemote("https://not-a-partner.example/some_network", [`${engine.top.base}::triage_desk`], null);
        return { pass: false, detail: "The runtime accepted an undeclared origin." };
      } catch (error) {
        return { pass: /allowed_peers/.test(error.message), detail: error.message };
      }
    },
  },
  {
    id: "cycle",
    title: "A composition cycle is stopped",
    spec: "§3.2 per-hop policy; §6",
    async run() {
      const engine = await topEngine();
      const desk = (await (await fetch(new URL("desks.json", base))).json())[0];
      const deskBase = new URL("./", desk.networkUrl).href.replace(/\/$/, "");
      const chain = [`${engine.top.base}::triage_desk`, engine.registry.cacheKey(deskBase, desk.network)];
      try {
        await engine.resolveRemote(desk.networkUrl, chain, null);
        return { pass: false, detail: "The runtime followed a cycle." };
      } catch (error) {
        return { pass: error.code === "COMPOSITION_CYCLE", detail: error.message };
      }
    },
  },
  {
    id: "depth",
    title: "Composition deeper than the runtime's limit is stopped",
    spec: "§3.1 bound execution",
    async run() {
      const engine = await topEngine();
      const desk = (await (await fetch(new URL("desks.json", base))).json())[0];
      const chain = ["a::1", "b::2", "c::3", "d::4", "e::5"];
      try {
        await engine.resolveRemote(desk.networkUrl, chain, null);
        return { pass: false, detail: "The runtime went deeper than its limit." };
      } catch (error) {
        return { pass: error.code === "COMPOSITION_DEPTH", detail: error.message };
      }
    },
  },
  {
    id: "budget",
    title: "Over-budget partner and agent calls are skipped, not run",
    spec: "§3.1 bound execution; §6",
    async run() {
      const c = composition();
      const lines = [];
      for (let i = 1; i <= 5; i++) {
        const reason = consumeRemoteBudget(c, `peer-${i}`);
        lines.push(`partner call ${i}: ${reason ? `skipped (${reason})` : "allowed"}`);
      }
      const again = consumeRemoteBudget(composition(), "same");
      const repeat = consumeRemoteBudget(Object.assign(composition(), { peerCalls: new Map([["same", 1]]) }), "same");
      lines.push(`same partner twice in one message: ${repeat ? `skipped (${repeat})` : "allowed"}`);
      const a = composition();
      let agentReason = null;
      for (let i = 0; i < 25 && !agentReason; i++) agentReason = consumeAgentBudget(a);
      lines.push(`agent call 25: skipped (${agentReason})`);
      const late = consumeRemoteBudget(Object.assign(composition(), { deadline: Date.now() - 1 }), "late");
      lines.push(`after 90 s: skipped (${late})`);
      const pass = again === null && /limit of 4/.test(lines[4]) && !!repeat && !!agentReason && !!late;
      return { pass, detail: lines.join("\n") };
    },
  },
  {
    id: "router",
    title: "A partner runs on the caller's router and cannot change it",
    spec: "§3.2 local execution; §4 router-only disclosure; §6",
    async run() {
      const caller = { baseUrl: "https://router.chosen-by-visitor.example/v1", mock: false, key: "never-copied" };
      const peer = selectPeerRouter(caller);
      const leaked = Object.keys(peer).filter(k => !["baseUrl", "mock"].includes(k));
      return {
        pass: peer.baseUrl === caller.baseUrl && leaked.length === 0,
        detail: `Peer router: ${peer.baseUrl}. The peer manifest's llm_router is not read. Fields passed to the peer: ${Object.keys(peer).join(", ")} (no key). Live evidence: the desk server logged 0 Authorization headers in the local live check (docs/evidence).`,
      };
    },
  },
  {
    id: "sly",
    title: "Private context does not reach a partner unless a field is allowed",
    spec: "§2.1 private context rules; §5; §6",
    async run() {
      const front = (await triageNetwork()).getAgentSpec("triage_desk");
      const allowed = allowedDownstreamSly(front) || [];
      const sent = filterSlyData({ session_token: "secret-1", visitor_email: "a@b.example", app_repo: "internal" }, allowed);
      return {
        pass: Object.keys(sent).length === 0,
        detail: `triage_desk allows ${allowed.length ? allowed.join(", ") : "no"} private fields downstream. What a partner would receive from {session_token, visitor_email, app_repo}: ${JSON.stringify(sent)}.`,
      };
    },
  },
];

function render(check, result) {
  const row = document.getElementById(`check-${check.id}`);
  row.querySelector(".verdict").textContent = result.pass ? "PASS" : "FAIL";
  row.querySelector(".verdict").className = `verdict ${result.pass ? "pass" : "fail"}`;
  row.querySelector("pre").textContent = result.detail;
}

export async function runAll() {
  const host = document.getElementById("check-list");
  host.textContent = "";
  for (const check of CHECKS) {
    const row = document.createElement("article");
    row.id = `check-${check.id}`;
    row.className = "check";
    row.innerHTML = `<header><h3></h3><span class="verdict">running…</span></header><p class="small"></p><pre></pre>`;
    row.querySelector("h3").textContent = check.title;
    row.querySelector("p").textContent = check.spec;
    host.append(row);
  }
  for (const check of CHECKS) {
    try {
      render(check, await check.run());
    } catch (error) {
      render(check, { pass: false, detail: `The check itself failed: ${error.message}` });
    }
  }
}

if (typeof window !== "undefined") {
  document.getElementById("run-checks").addEventListener("click", runAll);
  runAll();
}
