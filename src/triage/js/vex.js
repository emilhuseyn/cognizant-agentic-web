// OpenVEX v0.2.0 statements and documents (https://github.com/openvex/spec).

export class Vex {
  static STATUSES = ["not_affected", "affected", "fixed", "under_investigation"];
  static JUSTIFICATIONS = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
  ];

  static purl(ecosystem, name, version) {
    if (ecosystem === "PyPI") return `pkg:pypi/${encodeURIComponent(name.toLowerCase().replace(/[-_.]+/g, "-"))}@${encodeURIComponent(version)}`;
    const scoped = name.startsWith("@") ? `%40${name.slice(1).split("/").map(encodeURIComponent).join("/")}` : encodeURIComponent(name);
    return `pkg:npm/${scoped}@${encodeURIComponent(version)}`;
  }

  // Check a decision the way OpenVEX requires it; returns null or a reason.
  static problem(decision) {
    if (!Vex.STATUSES.includes(decision.status)) return `Status must be one of ${Vex.STATUSES.join(", ")}.`;
    if (decision.status === "not_affected" && !decision.justification && !decision.impactStatement) {
      return "not_affected needs a justification or an impact statement.";
    }
    if (decision.justification && !Vex.JUSTIFICATIONS.includes(decision.justification)) {
      return `Justification must be one of ${Vex.JUSTIFICATIONS.join(", ")}.`;
    }
    if (decision.justification && decision.status !== "not_affected") return "A justification only goes with not_affected.";
    if (decision.status === "affected" && !decision.actionStatement) return "affected needs an action statement, such as the upgrade you plan.";
    return null;
  }

  static statement(finding, decision, productId) {
    const s = {
      vulnerability: { name: finding.advisoryId, ...(finding.aliases?.length ? { aliases: finding.aliases } : {}) },
      products: [{ "@id": productId, subcomponents: [{ "@id": Vex.purl(finding.ecosystem, finding.package, finding.version) }] }],
      status: decision.status,
      timestamp: decision.decidedAt,
    };
    if (decision.justification) s.justification = decision.justification;
    if (decision.impactStatement) s.impact_statement = decision.impactStatement;
    if (decision.actionStatement) s.action_statement = decision.actionStatement;
    const notes = (decision.evidence || []).map(e => `${e.source}${e.origin ? ` (${e.origin})` : ""}: ${e.text}`);
    if (notes.length) s.status_notes = notes.join(" | ").slice(0, 2000);
    return s;
  }

  static async digest(text) {
    const bytes = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  static async document({ author, productId, statements, timestamp }) {
    const body = JSON.stringify(statements);
    const id = await Vex.digest(`${productId}|${timestamp}|${body}`);
    return {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": `urn:uuid:${id.slice(0, 8)}-${id.slice(8, 12)}-${id.slice(12, 16)}-${id.slice(16, 20)}-${id.slice(20, 32)}`,
      author: author || "Unknown author",
      role: "Document creator",
      timestamp,
      version: 1,
      tooling: "Triage Desk (Maintainer Desk, Open Agentic Web Challenge)",
      statements,
    };
  }
}
