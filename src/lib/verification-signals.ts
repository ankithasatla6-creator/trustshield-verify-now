import type { VerifyResult } from "@/types/analysis";

// Presentation-only signals; the API remains the authority for the result label.
export function verificationSignals(result: VerifyResult) {
  const value = result.identifier.trim().toLowerCase();
  const upi = /^[a-z0-9._-]+@(?:upi|ybl|paytm|apl|okhdfcbank|oksbi|okaxis|okicici|ibl|fbl)$/i.test(value);
  const email = !upi && /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(value);
  let host = "";
  if (!upi && !email) {
    try {
      host = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`).hostname.replace(/^www\./, "");
    } catch {
      // Plain organization names and phone numbers are not web addresses.
    }
  }
  const social = /^(?:[a-z0-9-]+\.)?(?:facebook|instagram|linkedin|twitter|x)\.com$/.test(host);
  const kind = upi ? "upi" : email ? "email" : social ? "social" : result.kind;
  const signals: string[] = [];
  if (email && /@(?:gmail|googlemail|outlook|hotmail|live|yahoo|ymail|aol|icloud|protonmail|proton)\./i.test(value)) signals.push("verifyPersonalEmail");
  if (host && /\.(?:xyz|top|click|icu|online|shop|win|loan|biz)$/.test(host)) signals.push("verifyRiskySuffix");
  if (host && (host.match(/-/g) ?? []).length >= 2) signals.push("verifyHyphens");
  if (upi && /refund|recovery|money-recovery|support/i.test(value.split("@")[0] ?? "")) signals.push("verifyUpiIndicator");
  if (result.label === "Reported Identifier") signals.push("verifyDemoReport");
  if (result.label === "Verified") signals.push("verifyStaticMatch");
  const guidance = kind === "upi" ? "verifyUpiGuidance" : kind === "phone" ? "verifyPhoneGuidance" : kind === "social" ? "verifySocialGuidance" : kind === "email" ? "verifyEmailGuidance" : "verifyWebsiteGuidance";
  return { kind, signals, guidance };
}