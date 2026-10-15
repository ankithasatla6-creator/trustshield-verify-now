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
    const result = mockVerifyResult("https://bank-security-login.xyz/account");
    expect(result.label).toBe("Suspicious");
    expect(result.evidence?.join(" ")).toMatch(/\.xyz/);
    expect(details.kind).toBe("website");
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
    expect(result.label).toBe("Known Official Domain");
    expect(verificationSignals(result).signals).toContain("verifyStaticMatch");
  });
  it.each(["google.com", "microsoft.com", "https://www.google.com/search", "mail.google.com"])("recognizes %s as a known official domain", (d) => {
    expect(mockVerifyResult(d).label).toBe("Known Official Domain");
  });
  it("flags g00gle-security-check.com as a look-alike", () => {
    const result = mockVerifyResult("g00gle-security-check.com");
    expect(result.label).toBe("Suspicious");
    expect(result.evidence?.join(" ")).toMatch(/google/);
  });
  it("does not flag hyphens alone", () => {
    expect(mockVerifyResult("my-local-bakery.com").label).toBe("Needs Verification");
  });
  it.each(["goo gle.com", "google..com", "-bad-.com", "http://"])("marks %s as an invalid domain", (d) => {
    expect(mockVerifyResult(d).label).toBe("Invalid Domain");
  });
  it.each(["sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "paytm.com", "phonepe.com", "npci.org.in", "amazon.in", "flipkart.com", "myntra.com", "meesho.com", "github.com", "linkedin.com", "coursera.org", "udemy.com", "naukri.com", "internshala.com", "apple.com", "infyspringboard.onwingspan.com"])("recognizes %s as official", (d) => {
    expect(mockVerifyResult(d).label).toBe("Known Official Domain");
  });
  it.each(["my-local-bakery.com", "sharma-tailors-hyderabad.in", "example.org", "sarkari-naukri-updates.com"])("treats %s as a neutral standard website", (d) => {
    const result = mockVerifyResult(d);
    expect(result.label).toBe("Needs Verification");
    expect(result.standardWebsite).toBe(true);
    expect(result.reason).toMatch(/Standard Website/);
  });
  it.each(["sbi.co.in.verify-login.xyz", "paytrn.com", "myntra-offers.shop", "flipkart-sale.com", "amaz0n.in", "g00gle-security-check.com"])("keeps %s suspicious and not official", (d) => {
    const result = mockVerifyResult(d);
    expect(result.label).toBe("Suspicious");
    expect(result.standardWebsite).toBeFalsy();
  });
});
