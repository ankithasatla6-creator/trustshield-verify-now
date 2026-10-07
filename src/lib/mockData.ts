import type { AnalysisResult, VerifyLabel, VerifyResult } from "@/types/analysis";

export const sampleMessages: Record<string, string> = {
  fakeInternship: "Congratulations! You are selected for a remote internship. Pay ₹4,999 registration fee today to confirm your place. Limited slots — send your Aadhaar and OTP now.",
  fakeBank: "URGENT: Your bank account will be blocked. Call our support agent and share the OTP to complete KYC immediately.",
  familyEmergency: "Mom, I lost my phone and I am in trouble. Please send ₹25,000 to this new UPI ID right now. Don't call me.",
  recovery: "We can recover all the money you lost. Pay a small processing fee first and we guarantee a full refund.",
  legitimateInternship: "Thank you for applying. Your interview is scheduled for Tuesday. Please join using the meeting link in your applicant portal. No payment is required.",
  delivery: "Your parcel is scheduled for delivery today. Track it in the official courier app using tracking ID IN482910.",
};

export const suspiciousResult: AnalysisResult = {
  riskScore: 91,
  severity: "VERY_HIGH",
  category: "Potential job / advance-fee scam",
  confidence: "high",
  redFlags: [
    { text: "Pay ₹4,999 registration fee", reason: "Legitimate employers rarely charge candidates to secure a role.", weight: "high" },
    { text: "Limited slots", reason: "Artificial urgency can pressure you to act before checking.", weight: "medium" },
    { text: "send your Aadhaar and OTP", reason: "Requests for identity documents and OTPs are a serious safety warning.", weight: "high" },
  ],
  recommendedActions: ["Do not send money or share personal information.", "Contact the organization using details from its official website.", "Save screenshots and block the sender if they continue pressuring you."],
  verificationSteps: ["Search the official careers page for the role.", "Check that the sender's email matches the official domain.", "Ask for a video interview and written offer without any fee."],
  paymentWarning: true,
};

export const safeResult: AnalysisResult = {
  riskScore: 12,
  severity: "LOW",
  category: "Routine notification",
  confidence: "moderate",
  redFlags: [{ text: "official courier app", reason: "Use the app independently rather than links in unexpected messages.", weight: "low" }],
  recommendedActions: ["Open the official app directly to check the information.", "Do not share an OTP with a caller or message sender."],
  verificationSteps: ["Compare the tracking ID with your order receipt.", "Contact the courier through its official website if unsure."],
  paymentWarning: false,
};

// Demo lists used until the backend's live checks are switched on.
const TRUSTED_IDENTIFIERS = ["cybercrime.gov.in", "1930", "hdfcbank.com", "sbi.co.in", "icici.com", "axisbank.com", "phonepe.com", "paypal.com", "amazon.com", "flipkart.com", "whatsapp.com"];
const REPORTED_IDENTIFIERS = ["refund-support@upi", "money-recovery@ybl", "secure-bank-update.xyz", "win-prize-top.click", "9999999999"];
const RISKY_SUFFIXES = [".xyz", ".top", ".click", ".icu", ".online", ".shop", ".win", ".loan", ".biz"];

export function mockVerifyResult(raw: string): VerifyResult {
  const identifier = raw.trim();
  const value = identifier.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/$/, "");
  const kind = value.includes("@") && /@(upi|ybl|paytm|apl|okhdfcbank|oksbi|okaxis|okicici|ibl|fbl)$/i.test(value)
    ? "upi"
    : /@/.test(value)
      ? "email"
      : /^\+?[\d\s-]{7,15}$/.test(value)
        ? "phone"
        : /^[a-z0-9.-]+\.[a-z]{2,}/i.test(value)
          ? "website"
          : "organization";

  let label: VerifyLabel = "Needs Verification";
  let reason = "We could not match this identifier to a trusted or reported record. Confirm it through an official channel before you rely on it.";

  if (REPORTED_IDENTIFIERS.includes(value)) {
    label = "Reported Identifier";
    reason = "This identifier appears in the demo list of records linked to reported scams.";
  } else if (TRUSTED_IDENTIFIERS.includes(value)) {
    label = "Verified";
    reason = "This is the official contact detail for the organization. Check the exact page you are on before entering anything.";
  } else if (/\.gov\.in$|\.gov$|\.edu\.in$|\.nic\.in$/.test(value)) {
    label = "Verified";
    reason = "This is a government domain. Check the exact page you are on before entering details.";
  } else if (RISKY_SUFFIXES.some((suffix) => value.endsWith(suffix)) || (value.match(/-/g) ?? []).length >= 2) {
    label = "Suspicious";
    reason = "The address matches patterns seen in disposable scam sites. Verify it through another channel.";
  } else if (/@(gmail|yahoo|outlook|hotmail)\./i.test(value)) {
    reason = "This is a personal email address. Organizations usually write from their own domain — confirm the sender another way.";
  }

  return { identifier, kind, label, reason, checkedAt: new Date().toLocaleString("en-IN"), liveChecks: false };
}
