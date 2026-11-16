# Live check, 16 Nov 2026 (local)

Setup: Triage Desk on `http://127.0.0.1:8080`, lanternmd desk on `http://localhost:8081`, tidecache desk
on `http://localhost:8082` (`scripts/serve.mjs`, request log on). Model: a free local model
(`gemma-4-e4b`, LM Studio) behind a local CORS proxy on `127.0.0.1:1235`, entered through the
page's AI model settings (BYOK) with a dummy local key.

Visitor message: "Ask the lanternmd maintainers' desk whether LANTERN-2026-0001 applies to our
lanternmd 3.0.2. We keep html off and only our own authors write posts."

## What ran (runtime trace, in order)

1. `triage_desk` model call on the visitor's router `127.0.0.1:1235` -> tool call `website_get_findings`.
2. `website_get_findings` (site action, read) -> 21 findings.
3. Model call -> tool call `lanternmd_security_desk` (the partner network).
4. Consent card: "Contact lanternmd maintainers on your behalf? localhost:8081", with the first 140
   characters of the request. While it waited, the desk server received **no** agent files (log below:
   the last desk request before the card was the page's own OSV feed read at page load).
5. After **Allow**: the desk's manifest, network JSON, links.json and bridge were fetched, and the
   desk's agents ran **in the Triage page's browser**: trace spans with origin `localhost:8081`
   (`lanternmd_desk` -> `advisory_notes`), each model call to router `127.0.0.1:1235`.
6. Back in `triage_desk`: tool call `website_propose_vex_statement` -> proposal P1 (not_affected,
   vulnerable_code_not_in_execute_path) staged on the page, not recorded until the visitor applies it.

## What the desk server received after Allow

| Method | Path | Status | Origin | Authorization header | Cookies |
|---|---|---|---|---|---|
| GET | `/agent-manifest.json` | 200 | http://127.0.0.1:8080 | False | - |
| GET | `/lanternmd_security_desk.network.json` | 200 | http://127.0.0.1:8080 | False | - |
| GET | `/links.json` | 200 | http://127.0.0.1:8080 | False | - |
| GET | `/bridge/action-bridge.html` | 200 | (frame) | False | - |
| GET | `/runtime/action-bridge.js` | 200 | http://localhost:8081 | False | - |
| GET | `/runtime/action-transport.js` | 200 | http://localhost:8081 | False | - |
| GET | `/runtime/actions.js` | 200 | http://localhost:8081 | False | - |
| GET | `/runtime/form-actions.js` | 200 | http://localhost:8081 | False | - |
| GET | `/runtime/discovered-actions.js` | 200 | http://localhost:8081 | False | - |
| GET | `/runtime/web-crypto.js` | 200 | http://localhost:8081 | False | - |
| GET | `/bridge/agent-manifest.json` | 200 | (frame) | False | - |

Across the whole session the desk server logged 75 requests and **0** carried an
Authorization header. The visitor's key went only to the selected router (spec section 4).

## Found along the way

- With LM Studio's default 4,096-token context the second model call overflowed. LM Studio sent an
  SSE `event: error` line; the runtime's stream parser (`runtime/llm.js`) skips lines it cannot use, so
  the agent ended with an empty answer and no visible error. Spec section 5 asks for failures to be
  reported. This is in the vendored runtime, which sites must not edit; noted as a limitation and a
  candidate upstream issue.
