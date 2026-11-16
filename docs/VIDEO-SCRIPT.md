# Video script (under 2 minutes)

Emil records his own voice over a screen recording of the hosted sites in a browser. The rules ask
for browser footage, the entrant explaining the project (not AI generated), a public YouTube upload,
and no third-party logos or copyrighted music. Use no music at all.

Target length 1:50. About 250 spoken words. Cut the waiting while the model answers; say so on
screen once ("model answer sped up") so nothing looks faked.

Before recording:
- Use a hosted model so answers take seconds (Otari key with `alibaba/qwen3.8-flash`, entered by
  Emil in AI model settings). Do the run once off camera to warm up.
- Open four tabs: Triage Desk, the lanternmd desk, Desk Kit, Spec Checks. Browser zoom 110%, a clean profile,
  no bookmarks bar, no other extensions visible.
- Close the AI model settings panel before recording, so the key field never shows.

| Time | Screen | Emil says |
|---|---|---|
| 0:00-0:15 | Triage Desk, findings table already loaded with the demo app | "Every scanner alert ends with one question: does this actually affect my app? Databases list the vulnerable versions. When the bug can really be reached is something only the maintainers know. I'm Emil, I research software supply chain security, and this is Maintainer Desk." |
| 0:15-0:30 | Scroll the table; hover a desk tag; point at the source column | "The Triage Desk reads my dependency files and asks OSV.dev which advisories affect each exact version. This is real data. Two packages here publish a maintainer desk, and their advisories come from the maintainers' own feed." |
| 0:30-0:55 | Type the question into the assistant; the consent card appears; click Allow | "I ask: we render lanternmd only from our own authors' posts, with html off. Does this advisory apply? The assistant wants to ask the lanternmd maintainers' desk. That is another website, so the browser asks me first and shows exactly what will be sent." |
| 0:55-1:15 | The answer appears; the agents panel shows the desk's agents; the proposal card appears on the page; click Apply | "The desk's agents run here, in my browser, on my own key. The desk never sees the key and runs no server. It answers: not affected, the vulnerable code is not in the execution path. The assistant only proposes this decision. I apply it." |
| 1:15-1:25 | Click Download OpenVEX; show the file briefly | "My decisions export as OpenVEX, a standard file that existing security tools read, with the maintainers cited as the source." |
| 1:25-1:40 | Switch to the lanternmd desk tab, then to Desk Kit | "For maintainers, this is the desk: their policy, every advisory with when it applies, and a private report form. The Desk Kit builds one from a single JSON file, in the browser, with no install." |
| 1:40-1:50 | Spec Checks tab, all checks green | "And every rule the spec asks us to prove, invalid networks, cycles, budgets, blocked origins, private data, runs live here. Maintainer Desk: security advisories that answer back." |

Word count check: read it aloud with a timer once before recording. If it runs over 1:55, drop the
OpenVEX row's second half first.
