/**
 * Domain checks for the Verify feature. Keep identical to server/src/domain-check.ts.
 * Static, offline rules only: no WHOIS, live reputation or security scan is performed.
 */
export type DomainLabel = "Known Official Domain" | "Suspicious" | "Needs Verification" | "Invalid Domain";
export type DomainCheck = { label: DomainLabel; host: string; reason: string; evidence: string[] };

// Curated reference list: exact registered domains → brand name. Add entries here.
export const OFFICIAL_DOMAINS: Record<string, string> = {
  "google.com": "Google", "microsoft.com": "Microsoft", "apple.com": "Apple", "amazon.com": "Amazon",
  "amazon.in": "Amazon", "flipkart.com": "Flipkart", "paypal.com": "PayPal", "whatsapp.com": "WhatsApp",
  "facebook.com": "Facebook", "instagram.com": "Instagram", "linkedin.com": "LinkedIn", "github.com": "GitHub",
  "youtube.com": "YouTube", "netflix.com": "Netflix", "hdfcbank.com": "HDFC Bank", "sbi.co.in": "SBI",
  "onlinesbi.sbi": "SBI", "icicibank.com": "ICICI Bank", "icici.com": "ICICI", "axisbank.com": "Axis Bank",
  "phonepe.com": "PhonePe", "paytm.com": "Paytm", "npci.org.in": "NPCI", "infosys.com": "Infosys",
  "tcs.com": "TCS", "wipro.com": "Wipro", "internshala.com": "Internshala",
};

const OFFICIAL_SUFFIXES = [".gov.in", ".gov", ".nic.in", ".edu.in", ".ac.in", ".res.in"];
const MULTI_PART_TLDS = ["co.in", "org.in", "net.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "co.uk", "com.au"];
const RISKY_TLDS = ["xyz", "top", "click", "icu", "online", "shop", "win", "loan", "biz"];
const LURE_WORDS = ["login", "verify", "secure", "security", "update", "account", "support", "kyc", "refund", "reward", "check", "alert"];

const BRANDS = Array.from(new Set(Object.keys(OFFICIAL_DOMAINS).map((d) => d.split(".")[0] ?? ""))).filter((b) => b.length >= 4);

function deconfuse(text: string): string {
  return text.replace(/0/g, "o").replace(/[1l|]/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/rn/g, "m").replace(/vv/g, "w");
}

function editDistance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0] ?? 0;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const temp = row[j] ?? 0;
      row[j] = Math.min((row[j] ?? 0) + 1, (row[j - 1] ?? 0) + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = temp;
    }
  }
  return row[b.length] ?? 0;
}

export function extractDomainHost(raw: string): string | null {
  let value = raw.trim().toLowerCase();
  if (!value || value.length > 253 || /\s/.test(value) || value.includes("@")) return null;
  if (!/^https?:\/\//.test(value)) value = `https://${value}`;
  let host: string;
  try { host = new URL(value).hostname; } catch { return null; }
  host = host.replace(/^www\./, "").replace(/\.$/, "");
  const labels = host.split(".");
  if (labels.length < 2) return null;
  if (!labels.every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l) || /^xn--[a-z0-9-]+$/.test(l))) return null;
  const tld = labels[labels.length - 1] ?? "";
  if (!/^[a-z]{2,24}$/.test(tld) && !/^xn--/.test(tld)) return null;
  return host;
}

export function registeredDomain(host: string): string {
  const labels = host.split(".");
  const lastTwo = labels.slice(-2).join(".");
  return MULTI_PART_TLDS.includes(lastTwo) && labels.length >= 3 ? labels.slice(-3).join(".") : lastTwo;
}

export function checkDomain(raw: string): DomainCheck {
  const host = extractDomainHost(raw);
  if (!host) {
    return { label: "Invalid Domain", host: "", reason: "This is not a valid domain name. Check the spelling, remove spaces and try again (for example: example.com).", evidence: ["The input could not be read as a domain: it is empty, contains spaces or invalid characters, or has no valid ending such as .com or .in."] };
  }
  const registered = registeredDomain(host);
  const brand = OFFICIAL_DOMAINS[registered];
  const evidence: string[] = [];

  if (brand || OFFICIAL_SUFFIXES.some((s) => host.endsWith(s))) {
    evidence.push(brand ? `The registered domain "${registered}" exactly matches the official ${brand} domain in TrustShield's reference list.` : `The domain ends with an official government or education suffix.`);
    if (host !== registered) evidence.push(`"${host}" is a subdomain of ${registered}. Subdomains are controlled by the owner of ${registered}.`);
    evidence.push("A known official domain does not prove that every page, message, link or account using it is safe.");
    return { label: "Known Official Domain", host, reason: `This matches a known official domain${brand ? ` (${brand})` : ""} in TrustShield's reference list. Still check the exact page and never share OTPs or passwords in response to a message.`, evidence };
  }

  const regLabels = registered.split(".");
  const name = regLabels[0] ?? "";
  const tld = regLabels.slice(1).join(".");
  const subLabels = host.split(".").slice(0, -regLabels.length);
  const tokens = name.split("-").filter(Boolean);
  let strong = false;

  for (const b of BRANDS) {
    const official = Object.keys(OFFICIAL_DOMAINS).find((d) => d.startsWith(`${b}.`)) ?? `${b}.com`;
    const lookalike = tokens.find((t) => t !== b && (deconfuse(t) === b || (t.length >= 5 && editDistance(t, b) === 1)));
    if (lookalike) { evidence.push(`"${lookalike}" looks like "${b}" with swapped or altered characters (official domain: ${official}).`); strong = true; break; }
    if (tokens.includes(b) || name === b) { evidence.push(`Uses the brand name "${b}" but is not the official ${official} domain.`); strong = true; break; }
    if (subLabels.some((s) => s === b || deconfuse(s) === b)) { evidence.push(`Places "${b}" in a subdomain, but the real domain is ${registered}, not ${official}.`); strong = true; break; }
  }

  const lures = tokens.concat(subLabels).filter((t) => LURE_WORDS.includes(t));
  if (lures.length) evidence.push(`Contains wording often used in phishing addresses: ${Array.from(new Set(lures)).join(", ")}.`);
  if (RISKY_TLDS.includes(tld)) evidence.push(`Ends with ".${tld}", an ending often used for short-lived scam sites.`);
  if (host.startsWith("xn--") || host.includes(".xn--")) { evidence.push("Uses encoded international characters (punycode), which can disguise look-alike letters."); strong = true; }

  if (strong || (lures.length > 0 && RISKY_TLDS.includes(tld))) {
    return { label: "Suspicious", host, reason: "This domain shows signs of imitating a well-known brand or a phishing pattern. Do not enter details; go to the official website by typing it yourself.", evidence };
  }
  if (evidence.length === 0) evidence.push("No match in the official reference list and no look-alike signals were found.");
  return { label: "Needs Verification", host, reason: "This domain is not in TrustShield's reference list of official domains. That alone does not make it unsafe — confirm it through the organization's official channels.", evidence };
}
