import type { AnalysisResult, RedFlag, Severity } from "./types.ts";

/**
 * Rule-based scam scorer.
 *
 * Every rule matches a phrase that actually appears in the input, so the
 * frontend can highlight the exact wording it flagged. Wording stays careful:
 * "potential scam", "high-risk pattern", "verification recommended" — never
 * accusations about a person.
 */
type Rule = {
  id: string;
  pattern: RegExp;
  reason: string;
  weight: RedFlag["weight"];
  points: number;
  category?: string;
  payment?: boolean;
};

const BASE_SCORE = 10;
const MIN_SCORE = 6;
const MAX_SCORE = 97;

const TEXT_RULES: Rule[] = [
  {
    id: "advance-fee",
    pattern:
      /(?:pay|send|transfer|deposit|submit)\s+(?:a\s+)?(?:small\s+)?(?:registration\s+|processing\s+|security\s+|advance\s+|delivery\s+|activation\s+)?(?:fee|charges?|amount|deposit|advance)/i,
    reason: "Legitimate employers and services rarely ask you to pay a fee first.",
    weight: "high",
    points: 28,
    category: "Potential job / advance-fee scam",
    payment: true,
  },
  {
    id: "money-amount",
    pattern: /(?:₹|rs\.?|inr)\s*[\d,]+|(?:amount\s+of|send|pay)\s+[\d,]+/i,
    reason: "The message asks for a specific sum of money.",
    weight: "high",
    points: 22,
    category: "Potential payment scam",
    payment: true,
  },
  {
    id: "secrets-request",
    pattern:
      /\b(?:otp|one[-\s]?time[-\s]?password|cvv|cvv2|pin\s*number|password)\b/i,
    reason: "No genuine support team asks for an OTP, PIN, CVV or password.",
    weight: "high",
    points: 26,
    category: "Potential impersonation / account takeover",
  },
  {
    id: "urgency",
    pattern:
      /\b(?:urgent|urgently|immediately|right\s+now|right\s+away|asap|act\s+now|within\s+\d+\s+(?:minutes|hours)|hurry|last\s+(?:chance|day|date)|limited\s+(?:slots?|time|offer|period)|expires?\s+today)\b/i,
    reason: "Artificial urgency can pressure you to act before checking.",
    weight: "medium",
    points: 14,
  },
  {
    id: "threat",
    pattern:
      /\b(?:blocked|will\s+be\s+blocked|suspended|suspension|cancelled|deactivated|arrest|warrant|legal\s+action|police|cyber\s+cell|penalty|fine|court)\b/i,
    reason: "Threats of blocks, fines or legal action are a common pressure tactic.",
    weight: "medium",
    points: 18,
    category: "Potential impersonation scam",
  },
  {
    id: "secrecy",
    pattern:
      /\b(?:do\s+not\s+call|don'?t\s+call|do\s+not\s+tell|don'?t\s+tell|keep\s+(?:it\s+)?(?:secret|quiet|confidential)|tell\s+no\s+one|share\s+(?:this|it)\s+with\s+no\s+one|do\s+not\s+inform)\b/i,
    reason: "Being asked to hide the conversation from family is a high-risk pattern.",
    weight: "high",
    points: 22,
  },
  {
    id: "payment-channel",
    pattern:
      /\b(?:new|different|other|temp|temporary)\s+(?:upi|bank|account|vpa)\s*(?:id)?\b|\b(?:upi\s*(?:id|number)?|vpa)\s*[:\-]?\s*[a-z0-9._-]+@(?:upi|ybl|paytm|apl|okhdfcbank|oksbi|okaxis|okicici|ibl|fbl)\b/i,
    reason: "Payment is being pushed to an account or UPI ID you were not expecting.",
    weight: "high",
    points: 20,
    category: "Potential payment-channel mismatch",
    payment: true,
  },
  {
    id: "too-good",
    pattern:
      /\b(?:congratulations|you\s+(?:have\s+)?(?:been\s+)?(?:selected|chosen|shortlisted)|winner|prize\s+(?:draw|bond)|lucky\s+draw|guaranteed\s+(?:job|refund|returns?|income|placement)|double\s+your|earn\s+(?:₹|rs\.?|inr)?\s*[\d,]+\s*(?:per|a|every)?\s*day|work\s+from\s+home)\b/i,
    reason: "Unusually generous offers are a classic lure for fake opportunities.",
    weight: "medium",
    points: 16,
    category: "Potential fake opportunity",
  },
  {
    id: "identity-documents",
    pattern:
      /\b(?:aadhaar|aadhar|pan\s+card|pan\s+number|passport|voter\s+id|driving\s+licen[cs]e|bank\s+details|account\s+number|ifsc|selfie\s+with|original\s+documents)\b/i,
    reason: "Identity documents and bank details should not be shared on request.",
    weight: "high",
    points: 22,
    category: "Potential identity document misuse",
  },
  {
    id: "recovery-offer",
    pattern:
      /\b(?:recover\s+(?:all\s+)?(?:the\s+|your\s+)?(?:money|funds|amount)|money\s+recovery|recovery\s+(?:agent|service|team|process)|full\s+refund|guaranteed\s+refund|claim\s+(?:your\s+)?(?:money|refund|amount)|get\s+your\s+money\s+back|we\s+guarantee(?:\s+a|\s+your)?\s*(?:full\s+)?refund)\b/i,
    reason:
      "Money-recovery offers that ask for a fee first are a known repeat-scam pattern.",
    weight: "high",
    points: 30,
    category: "Potential recovery scam",
    payment: true,
  },
  {
    id: "crypto-giftcards",
    pattern:
      /\b(?:gift\s+card|google\s+play\s+card|steam\s+card|crypto|bitcoin|btc|usdt|binance|wallet\s+address)\b/i,
    reason: "Gift cards and crypto transfers cannot be reversed once sent.",
    weight: "high",
    points: 24,
    category: "Potential payment scam",
    payment: true,
  },
  {
    id: "kyc-pressure",
    pattern:
      /\b(?:complete\s+(?:your\s+)?kyc|update\s+(?:your\s+)?kyc|kyc\s+(?:is\s+)?(?:pending|expired|required)|share\s+(?:your\s+)?kyc)\b/i,
    reason: "KYC reminders pushed through messages are a common impersonation tactic.",
    weight: "medium",
    points: 14,
    category: "Potential impersonation scam",
  },
  {
    id: "off-platform",
    pattern:
      /\b(?:whatsapp|telegram|google\s+meet|zoom|personal\s+number|gmail\.com|@gmail)\b/i,
    reason: "Contact moved to a personal messenger instead of an official channel.",
    weight: "low",
    points: 10,
  },
  {
    id: "no-payment-claimed",
    pattern:
      /\b(?:no\s+payment\s+(?:is\s+)?required|no\s+fee|no\s+charges?|free\s+of\s+charge|never\s+ask\s+for\s+(?:money|payment|an?\s+otp|your\s+password))\b/i,
    reason: "It states that no payment is required, which lowers the risk estimate.",
    weight: "low",
    points: -20,
  },
  {
    id: "official-channel",
    pattern:
      /\b(?:official\s+(?:website|app|portal|courier|helpline|careers?\s+page)|applicant\s+portal|scheduled\s+for\s+delivery|tracking\s+(?:id|number)|order\s+receipt|meeting\s+link|video\s+interview)\b/i,
    reason: "It points to an official channel you can check independently.",
    weight: "low",
    points: -14,
  },
  {
    id: "interview-language",
    pattern:
      /\b(?:interview\s+is\s+scheduled|your\s+interview|scheduled\s+for\s+(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday|next))\b/i,
    reason: "It refers to a scheduled interview, which is normal hiring language.",
    weight: "low",
    points: -10,
  },
];

const CATEGORY_ACTIONS: Record<string, string[]> = {
  "Potential job / advance-fee scam": [
    "Ask for a written offer and a video interview before any payment.",
    "Check the role on the organization's official careers page.",
  ],
  "Potential payment scam": [
    "Stop the payment until you have verified the recipient independently.",
  ],
  "Potential payment-channel mismatch": [
    "Check the UPI ID or account name matches the person or organization you intended to pay.",
  ],
  "Potential impersonation / account takeover": [
    "Never share an OTP, PIN, CVV or password with anyone.",
  ],
  "Potential impersonation scam": [
    "Open the official app or website yourself to check the account status.",
  ],
  "Potential recovery scam": [
    "Do not pay a fee to someone offering to recover money you lost.",
  ],
  "Potential fake opportunity": [
    "Treat an unusually generous offer as a reason to verify, not to hurry.",
  ],
  "Potential identity document misuse": [
    "Ask why the document is needed and confirm the request through an official channel.",
  ],
};

const BASE_ACTIONS = [
  "Do not send money or share personal information until you have verified the sender.",
  "Contact the organization using a phone number or website you found yourself.",
  "Save screenshots of the message, then block the sender if the pressure continues.",
];

const BASE_STEPS = [
  "Search for the organization independently and use the contact details from its official page.",
  "Ask a family member or friend to look at the message with you.",
  "If money is involved, call 1930 or report at cybercrime.gov.in before you pay.",
];

function clip(value: string, max = 90): string {
  const trimmed = value.trim();
  return trimmed.length <= max ? trimmed : `${trimmed.slice(0, max - 1).trim()}…`;
}

function toSeverity(score: number): Severity {
  if (score >= 80) return "VERY_HIGH";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "CAUTION";
  return "LOW";
}

const WEIGHT_RANK: Record<RedFlag["weight"], number> = { high: 0, medium: 1, low: 2 };

function buildResult(
  hits: { rule: Rule; text: string; points?: number }[],
  fallbackCategory: string,
): AnalysisResult {
  const positive = hits.filter((hit) => hit.rule.points > 0);
  const rawScore = BASE_SCORE + hits.reduce((sum, hit) => sum + hit.rule.points, 0);
  const riskScore = Math.max(MIN_SCORE, Math.min(MAX_SCORE, Math.round(rawScore)));

  const redFlags = hits
    .map((hit) => ({
      text: hit.text,
      reason: hit.rule.reason,
      weight: hit.rule.weight,
    }))
    .sort(
      (a, b) => WEIGHT_RANK[a.weight] - WEIGHT_RANK[b.weight] || a.text.length - b.text.length,
    );

  if (redFlags.length === 0) {
    redFlags.push({
      text: "No strong risk pattern found",
      reason:
        "The content does not match the common scam patterns we check. Verification is still recommended.",
      weight: "low",
    });
  }

  const topCategory = [...positive].sort((a, b) => b.rule.points - a.rule.points).find(
    (hit) => hit.rule.category,
  );
  const category =
    topCategory?.rule.category ?? (riskScore >= 30 ? "High-risk pattern" : fallbackCategory);

  const highCount = positive.filter((hit) => hit.rule.weight === "high").length;
  const confidence = highCount >= 2 ? "high" : highCount === 1 || positive.length >= 3 ? "moderate" : "low";

  const actions = [...BASE_ACTIONS, ...positive.flatMap((hit) => CATEGORY_ACTIONS[hit.rule.category ?? ""] ?? [])];
  const recommendedActions = [...new Set(actions)].slice(0, 5);
  const verificationSteps = [...new Set(BASE_STEPS)].slice(0, 4);

  return {
    riskScore,
    severity: toSeverity(riskScore),
    category,
    confidence,
    redFlags,
    recommendedActions,
    verificationSteps,
    paymentWarning: positive.some((hit) => hit.rule.payment === true),
  };
}

export function analyzeMessage(text: string): AnalysisResult {
  const hits = TEXT_RULES.flatMap((rule) => {
    const match = rule.pattern.exec(text);
    return match && match[0] ? [{ rule, text: clip(match[0]) }] : [];
  });
  return buildResult(hits, "Routine notification");
}

const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "cutt.ly",
  "rb.gy",
  "rebrand.ly",
]);

const RISKY_TLDS = [
  ".xyz",
  ".top",
  ".click",
  ".icu",
  ".online",
  ".shop",
  ".live",
  ".win",
  ".biz",
  ".info",
  ".loan",
];

const TRUSTED_SUFFIXES = [".gov.in", ".gov", ".edu.in", ".ac.in", ".res.in", ".nic.in"];

const TRUSTED_HOSTS = new Set([
  "cybercrime.gov.in",
  "hdfcbank.com",
  "sbi.co.in",
  "icici.com",
  "axisbank.com",
  "phonepe.com",
  "paypal.com",
  "amazon.com",
  "flipkart.com",
  "whatsapp.com",
]);

const BRANDS = [
  "paypal",
  "amazon",
  "flipkart",
  "hdfc",
  "sbi",
  "icici",
  "axis",
  "phonepe",
  "gpay",
  "whatsapp",
  "cybercrime",
];

const URL_KEYWORD = /\b(?:login|verify|secure|update|confirm|password|otp|refund|claim|winner|prize|free|gift)\b/i;

export function analyzeLink(raw: string): AnalysisResult {
  const url = new URL(raw);
  const host = url.hostname.toLowerCase();
  const path = `${url.pathname}${url.search}`.toLowerCase();
  const hits: { rule: Rule; text: string }[] = [];

  const add = (
    id: string,
    text: string,
    reason: string,
    weight: RedFlag["weight"],
    points: number,
    extra: { category?: string; payment?: boolean } = {},
  ) => hits.push({ rule: { id, pattern: /x/, reason, weight, points, ...extra }, text });

  if (url.protocol === "http:") {
    add("http", "http://", "The link is not encrypted, so the page can be imitated easily.", "medium", 18);
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    add("ip-host", host, "A raw IP address instead of a domain name is a high-risk pattern.", "high", 30);
  }
  if (host.includes("xn--")) {
    add("punycode", host, "Look-alike characters in a domain name can hide the real brand.", "high", 25);
  }
  if (raw.includes("@")) {
    add("at-sign", "@", "An address that embeds a login name can send you somewhere unexpected.", "high", 25);
  }
  if (SHORTENERS.has(host)) {
    add("shortener", host, "Shortened links hide the final destination until you open them.", "medium", 16);
  }
  if (RISKY_TLDS.some((tld) => host.endsWith(tld))) {
    add("risky-tld", host, "This domain ending is common in disposable scam sites.", "medium", 14);
  }
  const brand = BRANDS.find((name) => host.includes(name));
  const isOfficial =
    TRUSTED_HOSTS.has(host) || TRUSTED_SUFFIXES.some((suffix) => host.endsWith(suffix));
  if (brand && !isOfficial) {
    add(
      "lookalike",
      host,
      "The domain looks close to a well-known brand but is not the official one.",
      "high",
      26,
      { category: "Potential impersonation scam" },
    );
  }
  if (isOfficial) {
    add(
      "trusted-domain",
      host,
      "This is the official domain for the organization. Still check the page you land on.",
      "low",
      -30,
    );
  }
  const keyword = URL_KEYWORD.exec(host + path);
  if (keyword && keyword[0]) {
    add(
      "keyword",
      keyword[0],
      "Words like this in a link are used by pages built to collect your details.",
      "medium",
      18,
    );
  }
  if ((host.match(/-/g) ?? []).length >= 2) {
    add("hyphens", host, "Hyphen-heavy domains are cheap to register and quick to throw away.", "medium", 12);
  }
  if (host.split(".").length > 3) {
    add("subdomains", host, "Deep subdomains can imitate a real site's address.", "medium", 10);
  }
  if (url.port) {
    add("port", `:${url.port}`, "A non-standard port is unusual for a normal service page.", "low", 8);
  }
  if (path.length > 60) {
    add("long-path", clip(path, 60), "Very long addresses are often used to hide tracking or redirect data.", "low", 8);
  }

  return buildResult(hits, "Routine link");
}
