import { describe, expect, it } from "vitest";
import { mockVerifyResult } from "@/lib/mockData";
import { verificationSignals } from "@/lib/verification-signals";

describe("Identifier presentation", () => {
  it.each(["ankithasatla6@gmail.com", "contact@outlook.com", "person@yahoo.com", "person@hotmail.com"])("keeps personal email %s uncertain", (identifier) => {
    const result = mockVerifyResult(identifier);
    expect(result.label).toBe("Needs Verification");
    expect(verificationSignals(result).signals).toContain("verifyPersonalEmail");
    expect(result.liveChecks).toBe(false);
  });
  it("explains exact website patterns even when the URL contains a path", () => {
    const details = verificationSignals(mockVerifyResult("https://bank-security-login.xyz/account"));
    expect(details.signals).toEqual(expect.arrayContaining(["verifyRiskySuffix", "verifyHyphens"]));
  });
  it("distinguishes UPI wording from proof of a reported owner", () => {
    const result = mockVerifyResult("refund-support@upi");
    expect(result.label).toBe("Reported Identifier");
    expect(verificationSignals(result).signals).toEqual(expect.arrayContaining(["verifyUpiIndicator", "verifyDemoReport"]));
  });
  it("offers phone guidance without making a live-check claim", () => {
    expect(verificationSignals(mockVerifyResult("9876543210")).guidance).toBe("verifyPhoneGuidance");
  });
  it("recognizes a social URL without changing the existing verdict", () => {
    const result = mockVerifyResult("https://instagram.com/example");
    expect(verificationSignals(result).guidance).toBe("verifySocialGuidance");
    expect(result.label).toBe("Needs Verification");
  });
  it("qualifies static Verified matches", () => {
    const result = mockVerifyResult("cybercrime.gov.in");
    expect(result.label).toBe("Verified");
    expect(verificationSignals(result).signals).toContain("verifyStaticMatch");
  });
});