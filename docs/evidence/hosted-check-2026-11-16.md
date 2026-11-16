# Hosted live check, 16 Nov 2026

Sites: Triage Desk `https://emilhuseyn.github.io/cognizant-agentic-web/`, desks
`https://lanternmd-desk.vercel.app/` and `https://tidecache-desk.vercel.app/`. Model: hosted Otari,
`alibaba/qwen3.8-flash`, with Emil's own key entered in the Triage page's AI model settings (the key
was never read, printed or stored by the operator). Each sample query ran as the first message of
a new chat, as the network's `sample_queries` promise.

| # | Sample query | What ran (runtime trace) | Result |
|---|---|---|---|
| 1 | Which findings in the demo app are critical or high, and what fixes them? | `website_get_findings`, answer | Correct table of the 2 critical and 4 high findings with fixed versions; noted one lodash upgrade clears three of them. |
| 2 | We render lanternmd only from our own authors' posts, with html left off. Does LANTERN-2026-0001 apply to us? | `website_get_findings`, `website_get_advisory`, consent card for `lanternmd-desk.vercel.app`, then the desk's `lanternmd_desk` and `advisory_notes` agents ran in this browser (origin `lanternmd-desk.vercel.app`, router `api.otari.ai`) | "Not affected": cites the advisory record and the maintainers' desk; warns that -0002 and -0003 are not covered by the same reasoning and suggests asking the desk about front matter. |
| 3 | Ask the tidecache maintainers whether TIDE-2026-0002 matters if we only use RedisBackend. | `website_get_findings`, consent card for `tidecache-desk.vercel.app`, desk agents in this browser | "Does not apply": vulnerable code not in the execute path; the desk's caveats (no DiskBackend fallback in tests or dev, no shared cache directory). |
| 4 | Propose a decision for the minimist finding: affected, we will upgrade to the fixed version. | `website_get_findings`, `website_get_advisory`, `vex_analyst`, `website_propose_vex_statement` | Proposal P1 (affected, upgrade to 1.2.6) shown under "Proposed decisions"; 0 decisions recorded until the visitor applies it. |
| 5 | Can you open a pull request that upgrades lodash for me? | `website_get_findings`, answer | Declined plainly ("this site can't touch your repo"), then listed the lodash findings and the versions that fix them. |

Totals for the five queries: 24 model calls, all to `api.otari.ai`, response model
`alibaba/qwen3.8-flash` (16 by the Triage Desk's agents, 4 by each desk's agents running in the
Triage page). Median call 9.1 s, longest 41.9 s. 96,014 prompt tokens and 15,681 completion tokens
(router usage figures).

## What the desks received

While each consent card waited, the browser had requested nothing from the desk beyond the OSV feed
the page reads at load. After Allow, the only requests to the desk origin were its public files:
`agent-manifest.json`, the network JSON, `links.json` and `bridge/action-bridge.html` (in a frame).
Every chat completion went to `api.otari.ai`. The key is stored for the Triage origin only, so the
desk origins have no access to it, and the runtime sends no Authorization header with peer file
requests (see the local check, where the desk server logged 0 Authorization headers in 75 requests).

## Found and fixed

- In queries 2 and 3 the desk's `advisory_notes` agent called `render_cruse` (the chat widget tool
  the runtime offers every agent) and got "Invalid info component" before answering in text. Its
  instructions, and `vex_analyst`'s, now say not to call any tool, `render_cruse` included.
- The console showed a 404 for the site icon; the pages now declare an empty inline icon.

Recheck after redeploying (same evening, query 3 again): `advisory_notes` answered without any tool
call, no errors in the trace, and the whole turn took 56 s instead of 79 s.
