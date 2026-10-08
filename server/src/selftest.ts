/**
 * Quick check of the scoring, case and verify modules.
 * Run with: npm test   (from the server folder)
 */
process.env.DATA_FILE = "/tmp/trustshield-selftest/cases.json";

const { analyzeLink, analyzeMessage } = await import("./scoring.ts");
const { createCase, getCase } = await import("./cases.ts");
const { verifyIdentifier } = await import("./verify.ts");

let failures = 0;

function check(label: string, passed: boolean, detail = ""): void {
  if (!passed) failures += 1;
  console.log(`${passed ? "PASS" : "FAIL"}  ${label}${detail ? `  (${detail})` : ""}`);
}

const samples: Record<string, string> = {
  fakeInternship:
    "Congratulations! You are selected for a remote internship. Pay ₹4,999 registration fee today to confirm your place. Limited slots — send your Aadhaar and OTP now.",
  fakeBank:
    "URGENT: Your bank account will be blocked. Call our support agent and share the OTP to complete KYC immediately.",
  familyEmergency:
    "Mom, I lost my phone and I am in trouble. Please send ₹25,000 to this new UPI ID right now. Don't call me.",
  recovery:
    "We can recover all the money you lost. Pay a small processing fee first and we guarantee a full refund.",
  legitimateInternship:
    "Thank you for applying. Your interview is scheduled for Tuesday. Please join using the meeting link in your applicant portal. No payment is required.",
  delivery:
    "Your parcel is scheduled for delivery today. Track it in the official courier app using tracking ID IN482910.",
};

console.log("\nMessage scores");
for (const [name, text] of Object.entries(samples)) {
  const result = analyzeMessage(text);
  console.log(
    `  ${name.padEnd(21)} ${String(result.riskScore).padStart(2)}/100  ${result.severity.padEnd(9)} ${result.category}`,
  );
}

const risky = analyzeMessage(samples.fakeInternship ?? "");
const safe = analyzeMessage(samples.legitimateInternship ?? "");

check("suspicious sample scores above 80", risky.riskScore >= 80, String(risky.riskScore));
check("suspicious sample warns about payment", risky.paymentWarning);
check("suspicious sample has high red flags", risky.redFlags.some((f) => f.weight === "high"));
check("legitimate sample scores below 30", safe.riskScore < 30, String(safe.riskScore));
check("legitimate sample has no payment warning", safe.paymentWarning === false);
check(
  "flagged phrases appear in the source text",
  risky.redFlags.every((flag) => (samples.fakeInternship ?? "").toLowerCase().includes(flag.text.toLowerCase())),
);
check("actions are never empty", risky.recommendedActions.length > 0);
check("verification steps are never empty", risky.verificationSteps.length > 0);

console.log("\nURL scores");
for (const url of [
  "https://cybercrime.gov.in",
  "http://cheap-laptop-offer.top/login",
  "https://bit.ly/3xYz",
]) {
  const result = analyzeLink(url);
  console.log(`  ${url.padEnd(38)} ${String(result.riskScore).padStart(2)}/100  ${result.severity}`);
}

check("government domain scores low", analyzeLink("https://cybercrime.gov.in").riskScore < 30);
check(
  "fake bank domain scores high",
  analyzeLink("http://cheap-laptop-offer.top/login").riskScore >= 60,
);

console.log("\nVerify labels");
for (const identifier of [
  "cybercrime.gov.in",
  "1930",
  "refund-support@upi",
  "someone@gmail.com",
  "cheap-laptop-offer.top",
]) {
  const result = verifyIdentifier(identifier);
  console.log(`  ${identifier.padEnd(24)} ${result.label}`);
}

check("official domain is verified", verifyIdentifier("cybercrime.gov.in").label === "Verified");
check("helpline is verified", verifyIdentifier("1930").label === "Verified");
check(
  "reported UPI is flagged",
  verifyIdentifier("refund-support@upi").label === "Reported Identifier",
);
check(
  "unknown personal email needs verification",
  verifyIdentifier("someone@gmail.com").label === "Needs Verification",
);
check(
  "throwaway domain is suspicious",
  verifyIdentifier("cheap-laptop-offer.top").label === "Suspicious",
);

console.log("\nCase building");
const record = createCase({
  whatHappened: "Paid for a internship that never started",
  amount: "4999",
  recipient: "fake-help@upi",
});
console.log(`  ${record.caseId} created at ${record.createdAt}`);
check("case id follows the TS-YYYY-NNN pattern", /^TS-\d{4}-\d{3}$/.test(record.caseId), record.caseId);
check("case is stored and readable", getCase(record.caseId)?.caseId === record.caseId);

const second = createCase({ whatHappened: "Second report" });
check("case numbers increase", second.caseId !== record.caseId, `${record.caseId} -> ${second.caseId}`);

console.log(
  failures === 0 ? "\nAll checks passed." : `\n${failures} check(s) failed.`,
);
process.exit(failures === 0 ? 0 : 1);
