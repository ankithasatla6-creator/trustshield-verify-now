export type Severity = "LOW" | "CAUTION" | "HIGH" | "VERY_HIGH";

export type AnalysisResult = {
  riskScore: number;
  severity: Severity;
  category: string;
  confidence: "low" | "moderate" | "high";
  redFlags: { text: string; reason: string; weight: "high" | "medium" | "low" }[];
  recommendedActions: string[];
  verificationSteps: string[];
  paymentWarning: boolean;
};

export type CaseData = Record<string, string>;

export type CaseResult = CaseData & { caseId: string; createdAt: string };

export type VerifyLabel =
  | "Verified"
  | "Needs Verification"
  | "Suspicious"
  | "Reported Identifier";

export type VerifyResult = {
  identifier: string;
  kind: string;
  label: VerifyLabel;
  reason: string;
  checkedAt: string;
  liveChecks: boolean;
};

export type FileKind = "screenshot" | "document";

export type FileAnalysisResult = AnalysisResult & { fileName: string; extractedText: string; explanation: string };
