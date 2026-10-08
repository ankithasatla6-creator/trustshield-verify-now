import { mockVerifyResult, safeResult, suspiciousResult } from "@/lib/mockData";
import type { AnalysisResult, FileAnalysisResult, FileKind, CaseData, CaseResult, VerifyResult } from "@/types/analysis";

// Set VITE_API_URL (see server/README.md) to use the real backend.
// With no value, this layer keeps serving the mock data so the site still runs.
const API_URL = (import.meta.env["VITE_API_URL"] ?? "").replace(/\/+$/, "");

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

export const FILE_LIMITS: Record<FileKind, { maxBytes: number; ext: string[]; accept: string }> = {
  screenshot: { maxBytes: 5 * 1024 * 1024, ext: ["png", "jpg", "jpeg"], accept: ".png,.jpg,.jpeg,image/png,image/jpeg" },
  document: { maxBytes: 10 * 1024 * 1024, ext: ["pdf", "doc", "docx"], accept: ".pdf,.doc,.docx,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
};

export function validateFile(kind: FileKind, file: File): "unsupported-type" | "too-large" | null {
  const ext = file.name.split(".").pop()?.toLowerCase() ?? "";
  if (!FILE_LIMITS[kind].ext.includes(ext)) return "unsupported-type";
  if (file.size > FILE_LIMITS[kind].maxBytes) return "too-large";
  return null;
}

async function toBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export async function analyzeFile(kind: FileKind, file: File, note = ""): Promise<FileAnalysisResult> {
  const invalid = validateFile(kind, file);
  if (invalid) throw new Error(invalid);
  if (isBackendEnabled) {
    return post<FileAnalysisResult>("/api/analyze/file", { kind, fileName: file.name, mimeType: file.type, data: await toBase64(file), note });
  }
  await wait(900);
  const base = note.trim() ? (/no payment|official/i.test(note) ? safeResult : suspiciousResult) : suspiciousResult;
  return { ...base, fileName: file.name, extractedText: note, explanation: "Demo result: connect the backend to read the file's text." };
}
