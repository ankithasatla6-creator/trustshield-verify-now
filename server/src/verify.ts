import type { VerifyLabel, VerifyResult } from "./types.ts";

/**
 * Identifier checks.
 *
 * The reported and trusted lists below are demo data shipped with the repo, not
 * a live threat feed. The result label is always one of the four the product
 * allows: Verified, Needs Verification, Suspicious, Reported Identifier.
 */
const REPORTED = new Map<string, string>([
  ["refund-support@upi", "This UPI ID appears in the demo list of identifiers linked to refund scams."],
  ["money-recovery@ybl", "This UPI ID appears in the demo list of identifiers linked to recovery scams."],
  ["secure-bank-update.xyz", "This domain appears in the demo list of identifiers used to imitate bank pages."],
  ["win-prize-top.click", "This domain appears in the demo list of identifiers used for prize scams."],
  ["9999999999", "This number appears in the demo list of identifiers reported for impersonation calls."],
]);

const TRUSTED = new Map<string, string>([
  ["cybercrime.gov.in", "Official portal for cyber crime reporting in India."],
  ["1930", "Official national cyber crime helpline number."],
  ["hdfcbank.com", "Official domain of this bank."],
  ["sbi.co.in", "Official domain of this bank."],
  ["icici.com", "Official domain of this bank."],
  ["axisbank.com", "Official domain of this bank."],
  ["phonepe.com", "Official domain of this payment app."],
  ["paypal.com", "Official domain of this payment service."],
  ["amazon.com", "Official domain of this marketplace."],
  ["flipkart.com", "Official domain of this marketplace."],
  ["whatsapp.com", "Official domain of this messaging service."],
]);

const TRUSTED_SUFFIXES = [".gov.in", ".gov", ".edu.in", ".ac.in", ".res.in", ".nic.in"];

const RISKY_TLDS = [".xyz", ".top", ".click", ".icu", ".online", ".shop", ".win", ".loan", ".biz"];

const UPI_PATTERN = /^[a-z0-9._-]+@(?:upi|ybl|paytm|apl|okhdfcbank|oksbi|okaxis|okicici|ibl|fbl)$/i;

export class VerifyValidationError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "VerifyValidationError";
  }
}

function classify(identifier: string): string {
  const value = identifier.toLowerCase();
  if (UPI_PATTERN.test(value)) return "upi";
  if (/@[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return "email";
  if (/^(?:https?:\/\/)?(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}(?:\/\S*)?$/i.test(value)) {
    if (/(?:facebook|instagram|linkedin|twitter|x)\.com\//i.test(value)) return "social";
    return "website";
  }
  if (/^\+?[\d\s-]{7,15}$/.test(value)) return "phone";
  return "organization";
}

function normalize(identifier: string): string {
  return identifier
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/$/, "");
}

export function verifyIdentifier(raw: string): VerifyResult {
  const identifier = raw.trim();
  if (identifier.length === 0) throw new VerifyValidationError("empty");
  if (identifier.length > 300) throw new VerifyValidationError("too-long");

  const kind = classify(identifier);
  const value = normalize(identifier);
  const host = value.replace(/\/.*$/, "");

  let label: VerifyLabel = "Needs Verification";
  let reason =
    "We could not match this identifier to a trusted or reported record. Confirm it through an official channel before you rely on it.";

  if (REPORTED.has(value) || REPORTED.has(host)) {
    label = "Reported Identifier";
    reason = REPORTED.get(value) ?? REPORTED.get(host) ?? reason;
  } else if (TRUSTED.has(value) || TRUSTED.has(host)) {
    label = "Verified";
    reason = TRUSTED.get(value) ?? TRUSTED.get(host) ?? reason;
  } else if (TRUSTED_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    label = "Verified";
    reason = "This is a government domain. Check the exact page you are on before entering details.";
  } else if (RISKY_TLDS.some((tld) => host.endsWith(tld)) || (host.match(/-/g) ?? []).length >= 2) {
    label = "Suspicious";
    reason =
      "The address matches patterns seen in disposable scam sites. Verify it through another channel.";
  } else if (kind === "email" && /@(?:gmail|yahoo|outlook|hotmail)\./.test(value)) {
    label = "Needs Verification";
    reason =
      "This is a personal email address. Organizations usually write from their own domain — confirm the sender another way.";
  }

  return {
    identifier,
    kind,
    label,
    reason,
    checkedAt: new Date().toLocaleString("en-IN"),
    liveChecks: false,
  };
}
