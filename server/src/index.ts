import cors from "cors";
import express, {
  type ErrorRequestHandler,
  type NextFunction,
  type Request,
  type Response,
} from "express";
import { CaseValidationError, createCase, getCase, listCases } from "./cases.ts";
import { analyzeLink, analyzeMessage } from "./scoring.ts";
import { VerifyValidationError, verifyIdentifier } from "./verify.ts";

const PORT = Number(process.env.PORT ?? 8787);
const RATE_LIMIT = Number(process.env.RATE_LIMIT_PER_MINUTE ?? 40);
const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS ?? "http://localhost:8080,http://127.0.0.1:8080"
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "256kb" }));
app.use(cors({ origin: ALLOWED_ORIGINS.includes("*") ? true : ALLOWED_ORIGINS }));

/** Small in-process token bucket so a demo cannot be hammered by one client. */
const buckets = new Map<string, { tokens: number; updatedAt: number }>();

function rateLimit(req: Request, res: Response, next: NextFunction): void {
  const key = req.ip ?? "unknown";
  const now = Date.now();
  const bucket = buckets.get(key) ?? { tokens: RATE_LIMIT, updatedAt: now };
  const refilled = ((now - bucket.updatedAt) / 60_000) * RATE_LIMIT;
  bucket.tokens = Math.min(RATE_LIMIT, bucket.tokens + refilled);
  bucket.updatedAt = now;

  if (bucket.tokens < 1) {
    buckets.set(key, bucket);
    res.status(429).json({ error: "rate-limited" });
    return;
  }

  bucket.tokens -= 1;
  buckets.set(key, bucket);
  next();
}

setInterval(
  () => {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [key, bucket] of buckets) {
      if (bucket.updatedAt < cutoff) buckets.delete(key);
    }
  },
  5 * 60 * 1000,
).unref();

function readString(body: unknown, field: string): string {
  if (typeof body !== "object" || body === null) return "";
  const value = (body as Record<string, unknown>)[field];
  return typeof value === "string" ? value.trim() : "";
}

app.get("/api/health", (_req: Request, res: Response) => {
  res.json({
    ok: true,
    service: "trustshield-api",
    version: "1.0.0",
    engine: "rule-based scorer v1",
    time: new Date().toISOString(),
  });
});

app.post("/api/analyze/text", rateLimit, (req: Request, res: Response) => {
  const text = readString(req.body, "text");
  if (text.length === 0) {
    res.status(422).json({ error: "empty" });
    return;
  }
  if (text.length > 20_000) {
    res.status(413).json({ error: "too-long" });
    return;
  }
  res.json(analyzeMessage(text));
});

app.post("/api/analyze/url", rateLimit, (req: Request, res: Response) => {
  const url = readString(req.body, "url");
  if (url.length === 0) {
    res.status(422).json({ error: "invalid-url" });
    return;
  }
  if (url.length > 2_000) {
    res.status(413).json({ error: "too-long" });
    return;
  }
  try {
    res.json(analyzeLink(url));
  } catch {
    res.status(422).json({ error: "invalid-url" });
  }
});

app.post("/api/verify", rateLimit, (req: Request, res: Response) => {
  const identifier = readString(req.body, "identifier");
  try {
    res.json(verifyIdentifier(identifier));
  } catch (error) {
    if (error instanceof VerifyValidationError) {
      res.status(error.code === "too-long" ? 413 : 422).json({ error: error.code });
      return;
    }
    throw error;
  }
});

app.post("/api/cases", rateLimit, (req: Request, res: Response) => {
  try {
    res.status(201).json(createCase((req.body as { data?: unknown })?.data ?? req.body));
  } catch (error) {
    if (error instanceof CaseValidationError) {
      res.status(error.code === "too-long" ? 413 : 422).json({ error: error.code });
      return;
    }
    throw error;
  }
});

app.get("/api/cases", (_req: Request, res: Response) => {
  res.json({ cases: listCases() });
});

app.get("/api/cases/:caseId", (req: Request, res: Response) => {
  const record = getCase(req.params.caseId ?? "");
  if (!record) {
    res.status(404).json({ error: "not-found" });
    return;
  }
  res.json(record);
});

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "not-found" });
});

const handleError: ErrorRequestHandler = (error, _req, res, _next) => {
  if (error instanceof SyntaxError) {
    res.status(400).json({ error: "invalid-json" });
    return;
  }
  console.error("[trustshield] unexpected error:", error);
  res.status(500).json({ error: "server-error" });
};

app.use(handleError);

app.listen(PORT, () => {
  console.log(`TrustShield API listening on http://localhost:${PORT}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(", ")}`);
});
