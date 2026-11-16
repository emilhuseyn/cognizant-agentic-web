// Registers the desk's operations with the agent runtime. agent-manifest.json loads this module
// through "actions.module"; the names in "actions.agentTools" become website_<name> tools.
// Each action wraps a DeskPage method that the page's own controls use too.
import { App } from "./desk-page.js";

class SiteActions {
  static registerActions(actions) {
    actions.register(SiteActions.policyAction());
    actions.register(SiteActions.checkVersionAction());
    actions.register(SiteActions.advisoryAction());
    actions.register(SiteActions.draftReportAction());
  }

  static policyAction() {
    return {
      name: "get_security_policy",
      description: "Read this project's security policy: supported version lines, the private security contact, what is out of scope, and the list of published advisories with ids, scores, affected ranges and fixed versions.",
      effect: "read",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      execute: () => App.page.getPolicy(),
    };
  }

  static checkVersionAction() {
    return {
      name: "check_version",
      description: "Check one exact version of this package against every published advisory's affected ranges. Returns the advisories whose range includes it, with the conditions under which each one applies, and the version's support status. It cannot know the visitor's settings.",
      effect: "read",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["version"],
        properties: {
          version: { type: "string", minLength: 1, maxLength: 40, description: "An exact version, such as 3.0.2." },
        },
      },
      execute: args => App.page.checkVersion(args.version),
    };
  }

  static advisoryAction() {
    return {
      name: "get_advisory",
      description: "Read one advisory in full: details, CVSS vector, affected ranges, fixed versions, when it applies, when it does not, and workarounds.",
      effect: "read",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["id"],
        properties: {
          id: { type: "string", enum: App.page.advisoryIds(), description: "Advisory id from website_get_security_policy." },
        },
      },
      execute: args => App.page.getAdvisory(args.id),
    };
  }

  static draftReportAction() {
    return {
      name: "draft_private_report",
      description: "Fill in this page's private vulnerability report form with the visitor's words. Nothing is sent: the visitor reviews the form and opens the email draft themselves. Returns the recipient and subject, or ok false with a reason.",
      effect: "write",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["summary"],
        properties: {
          summary: { type: "string", minLength: 3, maxLength: 120, description: "One line: what is wrong." },
          affectedVersion: { type: "string", maxLength: 40, description: "The exact version the visitor tested, if they gave one." },
          details: { type: "string", maxLength: 4000, description: "Steps to reproduce and the settings used, in the visitor's words." },
          impact: { type: "string", maxLength: 1000, description: "What an attacker could do, in the visitor's words." },
        },
      },
      execute: args => App.page.draftReport(args),
    };
  }
}

export const registerActions = SiteActions.registerActions;
