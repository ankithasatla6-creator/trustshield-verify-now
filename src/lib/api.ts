import { mockVerifyResult, safeResult, suspiciousResult } from "@/lib/mockData";
import type { AnalysisResult, CaseData, CaseResult, VerifyResult } from "@/types/analysis";

// Set VITE_API_URL (see server/README.md) to use the real backend.
// With no value, this layer keeps serving the mock data so the site still runs.
const API_URL = (import.meta.env.VITE_API_URL ?? "").replace(/\/+$/, "");

export const isBackendEnabled = API_URL.length > 0;

const wait = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function post<T>(path: string, payload: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new Error("unreachable");
  }
  if (!response.ok) {
    const detail: unknown = await response.json().catch(() => null);
    const code =
      detail && typeof detail === "object" && "error" in detail && typeof detail.error === "string"
        ? detail.error
        : "unreachable";
    throw new Error(code);
  }
  return (await response.json()) as T;
}

export async function analyzeText(text: string): Promise<AnalysisResult> {
  if (isBackendEnabled) return post<AnalysisResult>("/api/analyze/text", { text });
  await wait(700);
  if (!text.trim()) throw new Error("empty");
  const likelySafe = /no payment|required|official courier|scheduled for delivery/i.test(text);
  return likelySafe ? safeResult : suspiciousResult;
}

export async function analyzeUrl(url: string): Promise<AnalysisResult> {
  if (isBackendEnabled) return post<AnalysisResult>("/api/analyze/url", { url });
  await wait(700);
  if (!/^https?:\/\//i.test(url)) throw new Error("invalid-url");
  return /official|gov\.in/i.test(url) ? safeResult : suspiciousResult;
}

export async function buildCase(data: CaseData): Promise<CaseResult> {
  if (isBackendEnabled) return post<CaseResult>("/api/cases", { data });
  await wait(450);
  return { ...data, caseId: "TS-2026-001", createdAt: new Date().toLocaleString("en-IN") };
}

export async function verifyIdentifier(identifier: string): Promise<VerifyResult> {
  if (isBackendEnabled) return post<VerifyResult>("/api/verify", { identifier });
  await wait(500);
  if (!identifier.trim()) throw new Error("empty");
  return mockVerifyResult(identifier);
}
