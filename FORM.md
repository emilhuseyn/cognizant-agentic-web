# Devpost form: Open Agentic Web Challenge

Account: ekviem1 (joined 16 Nov 2026, solo). Deadline: 11 Jan 2027 08:00 PST = 20:00 Baku. Submit is
Emil's click; the operator never presses it. The standard Devpost fields are below; the
hackathon-specific questions are inferred from the Requirements on the overview page and must be
checked against the live form when it is opened while logged in.

## Before the form

- [ ] Sites hosted over HTTPS on three origins (Emil's yes needed: see the open decisions in DESIGN.md).
- [ ] `config/environments.json` prod URLs filled, `node scripts/build_all.mjs --env prod --check` green,
      `check_partner.mjs` on both hosted desk URLs from the hosted Triage origin, tests green.
- [ ] Repository public (Emil's yes needed), with README, LICENSE and NOTICE.
- [ ] Live run on the hosted sites with a real key (Otari or other), one full flow per sample query.
- [ ] Video recorded by Emil (VIDEO-SCRIPT.md), uploaded to YouTube as Public.
- [ ] Screenshots taken from the hosted sites (list below).

## Fields

| Field | Value |
|---|---|
| Project name | Maintainer Desk |
| Elevator pitch (short tagline) | Security advisories that answer back: maintainers publish a free agentic desk, and developers' triage agents ask it whether a vulnerability really affects them. |
| Thumbnail | `screenshots/01-triage.png` cropped to 3:2 |
| About the project | Paste DEVPOST.md from "## Inspiration" to the end (Markdown). |
| Built with (tags) | javascript, html5, css3, open-agentic-web, nsdeploy, neuro-san, hocon, osv, openvex, cvss, node.js |
| Try it out: links | 1. Triage Desk `<prod triage URL>` 2. lanternmd desk `<prod lanternmd URL>` 3. tidecache desk `<prod tidecache URL>` 4. Desk Kit `<prod triage URL>kit.html` 5. Spec Checks `<prod triage URL>checks.html` 6. GitHub repository `https://github.com/emilhuseyn/cognizant-agentic-web` |
| Video demo link | `<YouTube URL>` (public, under 2 minutes) |
| Image gallery | the screenshots below, in this order |
| Team | ekviem1 only |

## Hackathon questions (inferred from the Requirements; check the live form)

| Question | Answer |
|---|---|
| URL of your public open agentic website | `<prod triage URL>` |
| Conforming .json file describing the agent network | `<prod triage URL>agent-manifest.json` and `<prod triage URL>triage_desk.network.json` (desks: `<desk URL>agent-manifest.json`) |
| Runtime that runs the network in the browser | `<prod triage URL>runtime/index.js` (the challenge's runtime, unchanged) |
| Interface to interact with the network | The "Ask the Triage Desk" chat on each page; other sites call the networks through `bridge/` |
| Interface to configure LLMs and keys | "AI model settings" in each chat panel (BYOK) |
| Interaction with the website / other sites / being called | Site actions `website_get_findings`, `website_get_advisory`, `website_propose_vex_statement`; calls both maintainer desks after consent; callable by any agentic site |
| Additional tools shared with the community | Desk Kit (`kit.html` and `kit/build_desk.mjs`), Spec Checks page (`checks.html`), local server with request log (`scripts/serve.mjs`). All in the public repository, Apache 2.0. |
| New project or significantly updated? | New: first commit 16 Nov 2026, after the submission period opened (11 Nov 2026). |
| Otari account email (only if Otari is used) | Emil's Otari sign-up email, if he uses his credits for the live run and the video. Leave empty otherwise. |
| A problem you faced with Otari and how it could improve (only if used) | Write from Emil's actual experience during the hosted run. Not drafted, because it has to be true. |
| Testing instructions | Open the Triage Desk; the demo app's findings load without any key. For the assistant, open AI model settings and paste a key for any OpenAI-compatible provider that allows browser calls (hosted Otari by default). Try: "We render lanternmd only from our own authors' posts, with html left off. Does LANTERN-2026-0001 apply to us?" Allow the card, then Apply the proposal. Spec Checks needs no key. |

## Screenshots to take (from the hosted sites)

1. `01-triage.png`: Triage Desk with the demo findings table.
2. `02-consent.png`: the consent card naming the lanternmd desk's host and the request.
3. `03-answer.png`: the assistant's answer citing the desk, and the "Proposed decisions" card.
4. `04-vex.png`: the Decisions table and the downloaded OpenVEX file.
5. `05-desk.png`: the lanternmd desk page (advisories with "affected only when").
6. `06-kit.png`: the Desk Kit page after "Check only".
7. `07-checks.png`: Spec Checks, all PASS.

## Disclosure (already in DEVPOST.md and README.md)

The code and text were written with an AI coding assistant (Claude, by Anthropic), directed and
reviewed by Emil; the runtime and build scripts are the organisers' work, used unchanged.
