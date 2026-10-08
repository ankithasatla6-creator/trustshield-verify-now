import { inflateRawSync, inflateSync } from "node:zlib";
import { analyzeMessage } from "./scoring.ts";
import type { AnalysisResult } from "./types.ts";

export class FileValidationError extends Error {
  constructor(public code: "invalid-file" | "too-large" | "unsupported-type" | "no-text") {
    super(code);
  }
}

export const FILE_RULES = {
  screenshot: { maxBytes: 5 * 1024 * 1024, ext: ["png", "jpg", "jpeg"], mime: ["image/png", "image/jpeg"] },
  document: {
    maxBytes: 10 * 1024 * 1024,
    ext: ["pdf", "doc", "docx"],
    mime: [
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ],
  },
} as const;

export type FileKind = keyof typeof FILE_RULES;

function signatureMatches(ext: string, buf: Buffer): boolean {
  const hex = buf.subarray(0, 8).toString("hex");
  if (ext === "png") return hex.startsWith("89504e470d0a1a0a");
  if (ext === "jpg" || ext === "jpeg") return hex.startsWith("ffd8ff");
  if (ext === "pdf") return buf.subarray(0, 5).toString("latin1") === "%PDF-";
  if (ext === "docx") return hex.startsWith("504b0304");
  if (ext === "doc") return hex.startsWith("d0cf11e0a1b11ae1");
  return false;
}

function pdfText(buf: Buffer): string {
  const raw = buf.toString("latin1");
  const chunks: string[] = [];
  const streamRe = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
  let m: RegExpExecArray | null;
  while ((m = streamRe.exec(raw))) {
    const data = Buffer.from(m[1] ?? "", "latin1");
    let content = "";
    try {
      content = inflateSync(data).toString("latin1");
    } catch {
      content = m[1] ?? "";
    }
    const strRe = /\(((?:\\.|[^\\)])*)\)\s*(?:Tj|'|")|\[((?:[^\]])*)\]\s*TJ/g;
    let s: RegExpExecArray | null;
    while ((s = strRe.exec(content))) {
      if (s[1] !== undefined) chunks.push(s[1]);
      else if (s[2]) chunks.push((s[2].match(/\(((?:\\.|[^\\)])*)\)/g) ?? []).map((p) => p.slice(1, -1)).join(""));
      chunks.push(" ");
    }
  }
  return chunks.join("").replace(/\\([()\\])/g, "$1").replace(/\\n/g, " ");
}

function docxText(buf: Buffer): string {
  // Find word/document.xml in the ZIP local file headers.
  let offset = 0;
  while (offset < buf.length - 30) {
    if (buf.readUInt32LE(offset) !== 0x04034b50) break;
    const method = buf.readUInt16LE(offset + 8);
    const compSize = buf.readUInt32LE(offset + 18);
    const nameLen = buf.readUInt16LE(offset + 26);
    const extraLen = buf.readUInt16LE(offset + 28);
    const name = buf.subarray(offset + 30, offset + 30 + nameLen).toString("utf8");
    const start = offset + 30 + nameLen + extraLen;
    if (name === "word/document.xml") {
      const data = buf.subarray(start, start + compSize);
      const xml = (method === 8 ? inflateRawSync(data) : data).toString("utf8");
      return xml.replace(/<\/w:p>/g, "\n").replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
    }
    if (compSize === 0) break;
    offset = start + compSize;
  }
  return "";
}

function docText(buf: Buffer): string {
  const utf16 = buf.toString("utf16le").match(/[\x20-\x7E\u0900-\u0C7F]{4,}/g) ?? [];
  const ascii = buf.toString("latin1").match(/[\x20-\x7E]{6,}/g) ?? [];
  return [...utf16, ...ascii].join(" ");
}

export type FileAnalysis = AnalysisResult & { fileName: string; extractedText: string; explanation: string };

export function analyzeFile(input: {
  kind: unknown;
  fileName: unknown;
  mimeType: unknown;
  data: unknown;
  note?: unknown;
}): FileAnalysis {
  const kind = input.kind;
  if (kind !== "screenshot" && kind !== "document") throw new FileValidationError("invalid-file");
  const rules = FILE_RULES[kind];
  const fileName = typeof input.fileName === "string" ? input.fileName.slice(0, 200) : "";
  const mimeType = typeof input.mimeType === "string" ? input.mimeType : "";
  const ext = fileName.split(".").pop()?.toLowerCase() ?? "";
  if (!(rules.ext as readonly string[]).includes(ext)) throw new FileValidationError("unsupported-type");
  if (mimeType && !(rules.mime as readonly string[]).includes(mimeType)) throw new FileValidationError("unsupported-type");
  if (typeof input.data !== "string" || input.data.length === 0) throw new FileValidationError("invalid-file");
  const buf = Buffer.from(input.data, "base64");
  if (buf.length > rules.maxBytes) throw new FileValidationError("too-large");
  if (!signatureMatches(ext, buf)) throw new FileValidationError("unsupported-type");

  const note = typeof input.note === "string" ? input.note.trim().slice(0, 5000) : "";
  let extracted = "";
  if (ext === "pdf") extracted = pdfText(buf);
  else if (ext === "docx") extracted = docxText(buf);
  else if (ext === "doc") extracted = docText(buf);
  extracted = extracted.replace(/\s+/g, " ").trim().slice(0, 20_000);

  const text = [extracted, note].filter(Boolean).join("\n");
  if (!text) {
    if (kind === "screenshot") {
      // No on-device text reading for images yet: return a careful, honest result.
      return {
        ...analyzeMessage("verification needed"),
        riskScore: 35,
        severity: "CAUTION",
        category: "Unreviewed screenshot",
        confidence: "low",
        redFlags: [],
        fileName,
        extractedText: "",
        explanation:
          "We received the image but could not read its words. Type the text you see in the screenshot to get a full check.",
      };
    }
    throw new FileValidationError("no-text");
  }
  const result = analyzeMessage(text);
  return {
    ...result,
    fileName,
    extractedText: text.slice(0, 4000),
    explanation:
      result.redFlags.length > 0
        ? `We found ${result.redFlags.length} warning sign(s) in this ${kind}. This is a high-risk pattern estimate, not proof.`
        : `We did not find common scam phrases in this ${kind}. Verification is still recommended.`,
  };
}
