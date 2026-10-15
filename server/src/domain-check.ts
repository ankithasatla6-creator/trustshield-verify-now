/**
 * Domain checks for the Verify feature. Keep identical to src/lib/domain-check.ts.
 * Static, offline rules only: no WHOIS, live reputation or security scan is performed.
 */
export type DomainLabel = "Known Official Domain" | "Suspicious" | "Needs Verification" | "Invalid Domain";
export type DomainCheck = { label: DomainLabel; host: string; reason: string; evidence: string[]; standardWebsite?: boolean };

// Curated reference list: exact registered domains → brand name. Add entries here.
export const OFFICIAL_DOMAINS: Record<string, string> = {
  // Banking, payments and government-backed finance (India)
  "sbi.co.in": "SBI", "onlinesbi.sbi": "SBI", "sbi.bank.in": "SBI", "hdfcbank.com": "HDFC Bank", "hdfc.bank.in": "HDFC Bank",
  "icicibank.com": "ICICI Bank", "icici.bank.in": "ICICI Bank", "icici.com": "ICICI", "axisbank.com": "Axis Bank", "axis.bank.in": "Axis Bank",
  "kotak.com": "Kotak Mahindra Bank", "pnbindia.in": "Punjab National Bank", "bankofbaroda.in": "Bank of Baroda",
  "rbi.org.in": "Reserve Bank of India", "npci.org.in": "NPCI", "bhimupi.org.in": "BHIM UPI",
  "paytm.com": "Paytm", "phonepe.com": "PhonePe", "razorpay.com": "Razorpay", "paypal.com": "PayPal",
  "lic.co.in": "LIC", "licindia.in": "LIC", "zerodha.com": "Zerodha", "groww.in": "Groww",
  // Shopping, food and travel (India)
  "amazon.in": "Amazon India", "flipkart.com": "Flipkart", "myntra.com": "Myntra", "meesho.com": "Meesho",
  "ajio.com": "AJIO", "nykaa.com": "Nykaa", "swiggy.com": "Swiggy", "zomato.com": "Zomato",
  "bigbasket.com": "BigBasket", "irctc.co.in": "IRCTC", "makemytrip.com": "MakeMyTrip", "jio.com": "Jio", "airtel.in": "Airtel",
  // Jobs, learning and internships
  "naukri.com": "Naukri", "internshala.com": "Internshala", "coursera.org": "Coursera", "udemy.com": "Udemy",
  "edx.org": "edX", "khanacademy.org": "Khan Academy", "swayam.gov.in": "SWAYAM", "nptel.ac.in": "NPTEL",
  "onwingspan.com": "Infosys Springboard", "infosys.com": "Infosys", "tcs.com": "TCS", "wipro.com": "Wipro",
  "linkedin.com": "LinkedIn", "indeed.com": "Indeed", "unstop.com": "Unstop",
  // Global technology and services
  "google.com": "Google", "microsoft.com": "Microsoft", "apple.com": "Apple", "amazon.com": "Amazon",
  "github.com": "GitHub", "youtube.com": "YouTube", "netflix.com": "Netflix", "whatsapp.com": "WhatsApp",
  "facebook.com": "Facebook", "instagram.com": "Instagram", "wikipedia.org": "Wikipedia", "openai.com": "OpenAI",
  "zoom.us": "Zoom", "dropbox.com": "Dropbox", "adobe.com": "Adobe", "x.com": "X", "twitter.com": "X",
};

// Common words that are also brand names; skipped for look-alike/brand-in-name checks to avoid false alarms.
const GENERIC_BRAND_WORDS = ["naukri", "indeed", "unstop", "zoom", "groww", "kotak"];

const OFFICIAL_SUFFIXES = [".gov.in", ".gov", ".nic.in", ".edu.in", ".ac.in", ".res.in"];
const MULTI_PART_TLDS = ["co.in", "org.in", "net.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "co.uk", "com.au"];
const RISKY_TLDS = ["xyz", "top", "click", "icu", "online", "shop", "win", "loan", "biz"];
const LURE_WORDS = ["login", "verify", "secure", "security", "update", "account", "support", "kyc", "refund", "reward", "check", "alert"];

const BRANDS = Array.from(new Set(Object.keys(OFFICIAL_DOMAINS).map((d) => d.split(".")[0] ?? ""))).filter((b) => b.length >= 4 && !GENERIC_BRAND_WORDS.includes(b));

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
  if (evidence.length === 0) {
    evidence.push("Not in TrustShield's curated list of official domains, and no look-alike or phishing patterns were found.");
    evidence.push("New or smaller websites are often simply absent from the list — unlisted does not mean fraudulent.");
    return { label: "Needs Verification", host, standardWebsite: true, reason: "Standard Website — no specific scam patterns detected by this check. This is not a safety guarantee; if you plan to pay or share personal details, confirm the site through the organization's official channels.", evidence };
  }
  return { label: "Needs Verification", host, reason: "This domain is not in TrustShield's reference list and shows some wording worth a closer look. Confirm it through the organization's official channels before entering details.", evidence };
}
