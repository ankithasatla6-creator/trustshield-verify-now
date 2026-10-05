import type { AnalysisResult } from "@/types/analysis";

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