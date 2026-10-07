import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { CaseRecord } from "./types.ts";

/**
 * Case store.
 *
 * Cases are written to a local JSON file so a hackathon demo keeps its records
 * across restarts without needing a database. Swap this module for a real
 * database when the backend is deployed — the exported signatures stay the same.
 */
const DATA_FILE = resolve(process.env.DATA_FILE ?? "data/cases.json");
const MAX_FIELDS = 40;
const MAX_VALUE_LENGTH = 2000;

type Store = { nextNumber: number; cases: CaseRecord[] };

function emptyStore(): Store {
  return { nextNumber: 1, cases: [] };
}

function load(): Store {
  if (!existsSync(DATA_FILE)) return emptyStore();
  try {
    const parsed = JSON.parse(readFileSync(DATA_FILE, "utf8")) as Partial<Store>;
    if (!Array.isArray(parsed.cases) || typeof parsed.nextNumber !== "number") {
      return emptyStore();
    }
    return { nextNumber: parsed.nextNumber, cases: parsed.cases };
  } catch {
    return emptyStore();
  }
}

function save(store: Store): void {
  mkdirSync(dirname(DATA_FILE), { recursive: true });
  const temp = `${DATA_FILE}.tmp`;
  writeFileSync(temp, JSON.stringify(store, null, 2));
  renameSync(temp, DATA_FILE);
}

function sanitize(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").trim();
}

export class CaseValidationError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "CaseValidationError";
  }
}

export function createCase(input: unknown): CaseRecord {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new CaseValidationError("invalid-case");
  }

  const cleaned: Record<string, string> = {};
  const entries = Object.entries(input as Record<string, unknown>);
  if (entries.length === 0 || entries.length > MAX_FIELDS) {
    throw new CaseValidationError("invalid-case");
  }

  for (const [key, value] of entries) {
    if (typeof value !== "string" || key.length === 0 || key.length > 60) {
      throw new CaseValidationError("invalid-field");
    }
    const safe = sanitize(value);
    if (safe.length > MAX_VALUE_LENGTH) throw new CaseValidationError("too-long");
    if (safe.length > 0) cleaned[key] = safe;
  }

  if (Object.keys(cleaned).length === 0) throw new CaseValidationError("empty-case");

  const store = load();
  const year = new Date().getFullYear();
  const caseId = `TS-${year}-${String(store.nextNumber).padStart(3, "0")}`;
  const record: CaseRecord = {
    ...cleaned,
    caseId,
    createdAt: new Date().toLocaleString("en-IN"),
  };

  store.nextNumber += 1;
  store.cases.push(record);
  save(store);

  return record;
}

export function getCase(caseId: string): CaseRecord | undefined {
  return load().cases.find((item) => item.caseId === caseId);
}

export function listCases(limit = 25): CaseRecord[] {
  return load()
    .cases.slice(-limit)
    .reverse();
}
