import { createFileRoute } from "@tanstack/react-router";
import { LoaderCircle, SearchCheck, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useI18n } from "@/i18n";
import { verifyIdentifier } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { VerifyLabel, VerifyResult } from "@/types/analysis";

export const Route = createFileRoute("/verify")({
  head: () => ({
    meta: [
      { title: "Verify Before You Trust — TrustShield AI" },
      { name: "description", content: "Check a phone number, email, website, UPI ID or organization before you trust it." },
      { property: "og:title", content: "Verify Before You Trust" },
      { property: "og:description", content: "Check contact and organization identifiers safely." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: VerifyPage,
});

const TONES: Record<VerifyLabel, string> = {
  Verified: "risk-low",
  "Needs Verification": "risk-caution",
  Suspicious: "risk-high",
  "Reported Identifier": "risk-critical",
};

const LABEL_KEYS: Record<VerifyLabel, string> = {
  Verified: "verified",
  "Needs Verification": "needsVerification",
  Suspicious: "suspicious",
  "Reported Identifier": "reportedIdentifier",
};

function VerifyPage() {
  const { t } = useI18n();
  const [value, setValue] = useState("");
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);

  async function submit() {
    setLoading(true);
    setError(false);
    setResult(null);
    try {
      setResult(await verifyIdentifier(value));
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page-wrap max-w-3xl">
      <p className="section-kicker">
        <SearchCheck />
        {t("verifyFirst")}
      </p>
      <h1>{t("verifyTitle")}</h1>
      <p className="page-intro">{t("verifyIntro")}</p>

      <section className="mt-8 border border-border bg-card p-5 shadow-sm">
        <label className="font-bold" htmlFor="identifier">
          {t("identifier")}
        </label>
        <Input
          id="identifier"
          value={value}
          onChange={(event) => {
            setValue(event.target.value);
            setResult(null);
            setError(false);
          }}
          className="mt-3 h-14 text-lg"
        />
        <Button disabled={!value.trim() || loading} onClick={submit} className="relative mt-4 min-h-14 w-full">
          <span className="absolute -right-1 -top-2 rounded-full bg-warning px-2 py-0.5 text-[10px] font-black text-warning-foreground">
            {t("comingSoon")}
          </span>
          {loading ? (
            <>
              <LoaderCircle className="animate-spin" />
              {t("verifying")}
            </>
          ) : (
            t("checkIdentifier")
          )}
        </Button>
        {error && (
          <p role="alert" className="mt-4 border-l-4 border-critical bg-critical-soft p-4 font-bold text-critical">
            {t("verifyError")}
          </p>
        )}
      </section>

      {result && (
        <section aria-live="polite" className={cn("mt-6 border-l-8 bg-card p-6 shadow-sm", TONES[result.label])}>
          <p className="flex items-center gap-2 text-sm font-black uppercase">
            {result.label === "Verified" ? <ShieldCheck aria-hidden="true" /> : <ShieldAlert aria-hidden="true" />}
            {t(LABEL_KEYS[result.label])}
          </p>
          <p className="mt-2 break-all text-xl font-bold text-foreground">{result.identifier}</p>
          <p className="mt-4 text-foreground">{result.reason}</p>
          <p className="mt-4 text-sm font-bold text-muted-foreground">
            {result.checkedAt} · {result.kind}
          </p>
          <p className="mt-3 font-bold">{t("liveSoon")}</p>
          <Button
            variant="outline"
            onClick={() => {
              setResult(null);
              setValue("");
            }}
            className="mt-5 min-h-14"
          >
            {t("startAgain")}
          </Button>
        </section>
      )}
    </div>
  );
}
