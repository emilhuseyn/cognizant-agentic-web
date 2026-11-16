// Mounts the assistant inside the page. Shared by the Triage Desk and every maintainer desk.
// Adapted from the agentify-website skill's templates/site.js (Apache 2.0). Changes: the greeting
// comes from the assistant section's data-greeting attribute, and no site action needs this
// page's own confirmation dialog (no action here is irreversible), so every confirmation, if a
// partner's action ever asks for one, goes to the runtime's dialog, which names the origin.

export class AssistantMount {
  static greetingText() {
    return document.querySelector("#assistant")?.dataset.greeting || "";
  }

  static async start() {
    const status = document.querySelector("#assistant-status");
    const siteBase = new URL("./", import.meta.url).href;
    try {
      const { boot } = await import("./runtime/index.js");
      const booted = await boot("#agent-app", {
        originUrl: siteBase,
        sandboxWorkerUrl: new URL("runtime/sandbox-worker.js", siteBase).href,
      });
      AssistantMount.engine = booted.engine;
      AssistantMount.defaultReview = booted.engine.onActionConfirm;
      booted.engine.onActionConfirm = AssistantMount.review;
      AssistantMount.defaultConsent = booted.engine.onConsent;
      booted.engine.onConsent = AssistantMount.consent;
      const needsKey = !booted.engine.mockLLM && (!booted.engine.byokKey || booted.engine.byokKey === "demo");
      status.textContent = needsKey
        ? "The assistant needs your AI provider key. Add it in AI model settings below. Everything else on this page works without it."
        : "Assistant connected to this page.";
      if (!needsKey) AssistantMount.greet();
      return booted.engine;
    } catch (error) {
      status.textContent = "The assistant could not load. You can still use the page directly.";
      console.error("Assistant startup failed", error);
      return null;
    }
  }

  static greet() {
    const first = document.querySelector("#ns-msgs .ns-msg.bot");
    const text = AssistantMount.greetingText();
    if (first && text) first.textContent = text;
  }

  // Every confirmation goes to the runtime's own dialog, which shows the action, its origin
  // and its exact arguments (spec section 3.1).
  static async review(items) {
    const confirmed = await AssistantMount.defaultReview(items);
    AssistantMount.keepFocusInChat();
    return confirmed;
  }

  static async consent(info) {
    const answer = AssistantMount.defaultConsent(info);
    AssistantMount.focusConsentCard();
    const decision = await answer;
    // Let the page log the contact (spec section 5, observable execution).
    window.dispatchEvent(new CustomEvent("assistant-consent", { detail: { info, decision } }));
    AssistantMount.keepFocusInChat();
    return decision;
  }

  static focusConsentCard() {
    const cards = document.querySelectorAll("#ns-msgs .ns-consent");
    const card = cards[cards.length - 1];
    const title = card ? card.querySelector(".ns-consent-title") : null;
    if (!title) return;
    card.setAttribute("role", "group");
    card.setAttribute("aria-label", title.textContent);
    const active = document.activeElement;
    if (active && active !== document.body && !active.closest("#agent-app")) return;
    title.tabIndex = -1;
    title.focus();
  }

  static keepFocusInChat() {
    if (document.activeElement === document.body || document.activeElement === null) {
      document.querySelector("#ns-input")?.focus();
    }
  }
}

if (typeof window !== "undefined") {
  await AssistantMount.start();
}
