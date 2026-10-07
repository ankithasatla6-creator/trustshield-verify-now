export type Severity = "LOW" | "CAUTION" | "HIGH" | "VERY_HIGH";

export type RedFlagWeight = "high" | "medium" | "low";

export type RedFlag = {
  text: string;
  reason: string;
  weight: RedFlagWeight;
};

export type AnalysisResult = {
  riskScore: number;
  severity: Severity;
  category: string;
  confidence: "low" | "moderate" | "high";
  redFlags: RedFlag[];
  recommendedActions: string[];
  verificationSteps: string[];
  paymentWarning: boolean;
};

export type CaseRecord = Record<string, string> & {
  caseId: string;
  createdAt: string;
};

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
