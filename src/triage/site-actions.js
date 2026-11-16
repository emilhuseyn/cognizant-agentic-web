// Registers the Triage Desk's operations with the agent runtime. agent-manifest.json loads this
// module through "actions.module"; the names in "actions.agentTools" become website_<name> tools.
import { App } from "./js/triage-page.js";
import { Vex } from "./js/vex.js";

class SiteActions {
  static registerActions(actions) {
    actions.register(SiteActions.findingsAction());
    actions.register(SiteActions.advisoryAction());
    actions.register(SiteActions.proposeAction());
  }

  static findingsAction() {
    return {
      name: "get_findings",
      description: "Read the dependency check on this page: the app name, each finding (key, advisory id, package@version, severity, fixed versions, source, maintainer desk tool if any, current decision), pending proposals, which maintainer desks exist and which were asked in this session.",
      effect: "read",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      execute: () => App.page.getFindings(),
    };
  }

  static advisoryAction() {
    return {
      name: "get_advisory",
      description: "Read one advisory among the current findings: details, aliases, CVSS vector, fixed versions, references, and whether its package's maintainers publish a desk to ask.",
      effect: "read",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["advisoryId"],
        properties: {
          advisoryId: { type: "string", minLength: 3, maxLength: 80, description: "An advisoryId from website_get_findings." },
        },
      },
      execute: args => App.page.getAdvisory(args.advisoryId),
    };
  }

  static proposeAction() {
    return {
      name: "propose_vex_statement",
      description: "Propose a VEX decision for one finding. It is NOT recorded: the page shows it under 'Proposed decisions' and the visitor applies or discards it. Cite a maintainer desk only after asking it in this session. Returns the proposal id, or ok false with a reason.",
      effect: "write",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["findingKey", "status", "evidence"],
        properties: {
          findingKey: { type: "string", minLength: 3, maxLength: 300, description: "The finding's key from website_get_findings." },
          status: { type: "string", enum: Vex.STATUSES },
          justification: { type: "string", enum: Vex.JUSTIFICATIONS, description: "Only with not_affected." },
          impactStatement: { type: "string", maxLength: 500, description: "One sentence on why the product is or is not affected." },
          actionStatement: { type: "string", maxLength: 500, description: "Required with affected: what the visitor will do, such as the upgrade." },
          evidence: {
            type: "array",
            minItems: 1,
            maxItems: 3,
            items: {
              type: "object",
              additionalProperties: false,
              required: ["source", "text"],
              properties: {
                source: { type: "string", enum: ["visitor", "maintainer desk", "advisory record"], description: "Who said it." },
                text: { type: "string", minLength: 3, maxLength: 600, description: "What they said, short." },
              },
            },
          },
        },
      },
      execute: args => App.page.proposeStatement(args),
    };
  }
}

export const registerActions = SiteActions.registerActions;
