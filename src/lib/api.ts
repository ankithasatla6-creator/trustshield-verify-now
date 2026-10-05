import { safeResult, suspiciousResult } from "@/lib/mockData";
import type { AnalysisResult, CaseData, CaseResult } from "@/types/analysis";

const wait = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds));

export async function analyzeText(text: string): Promise<AnalysisResult> {
  await wait(700);
  if (!text.trim()) throw new Error("empty");
  const likelySafe = /no payment|required|official courier|scheduled for delivery/i.test(text);
  return likelySafe ? safeResult : suspiciousResult;
}

export async function analyzeUrl(url: string): Promise<AnalysisResult> {
  await wait(700);
  if (!/^https?:\/\//i.test(url)) throw new Error("invalid-url");
  return /official|gov\.in/i.test(url) ? safeResult : suspiciousResult;
}

export async function buildCase(data: CaseData): Promise<CaseResult> {
  await wait(450);
  return { ...data, caseId: "TS-2026-001", createdAt: new Date().toLocaleString("en-IN") };
}