import { createFileRoute } from "@tanstack/react-router";
import { LoaderCircle, Search, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useI18n } from "@/i18n";
import { analyzeText, analyzeUrl } from "@/lib/api";
import { sampleMessages } from "@/lib/mockData";
import type { AnalysisResult, FileAnalysisResult } from "@/types/analysis";
import { FileUploadPanel } from "@/components/analysis/FileUploadPanel";
import { RiskScoreCard } from "@/components/analysis/RiskScoreCard";
import { RedFlagList } from "@/components/analysis/RedFlagList";
import { HighlightedText } from "@/components/analysis/HighlightedText";
import { ActionPanel } from "@/components/analysis/ActionPanel";

export const Route = createFileRoute("/analyze")({ head: () => ({ meta: [{ title: "Analyze a Message or URL — TrustShield AI" }, { name: "description", content: "Check suspicious messages and links for high-risk patterns." }, { property: "og:title", content: "Analyze with TrustShield AI" }, { property: "og:description", content: "Check suspicious content before you trust it." }, { property: "og:type", content: "website" }, { name: "twitter:card", content: "summary_large_image" }] }), component: AnalyzePage });

function AnalyzePage() {
  const { t } = useI18n();
  const [tab, setTab] = useState("message"); const [value, setValue] = useState(""); const [result, setResult] = useState<AnalysisResult | FileAnalysisResult | null>(null); const [loading, setLoading] = useState(false); const [error, setError] = useState(false);
  const tabs = ["message", "url", "screenshot", "document"] as const;
  const samples = [["fakeInternship", "fakeInternship"], ["fakeBank", "fakeBank"], ["familyEmergency", "familyEmergency"], ["recoveryScam", "recovery"], ["legitimateInternship", "legitimateInternship"], ["deliveryNotification", "delivery"]] as const;
  async function submit() { setLoading(true); setError(false); setResult(null); try { setResult(tab === "url" ? await analyzeUrl(value) : await analyzeText(value)); } catch { setError(true); } finally { setLoading(false); } }
  return <div className="page-wrap"><header className="max-w-2xl"><p className="section-kicker"><ShieldAlert/> {t("verifyFirst")}</p><h1>{t("analysisTitle")}</h1><p className="page-intro">{t("analysisIntro")}</p></header>
    <section className="mt-8 border border-border bg-card p-4 shadow-sm sm:p-6"><div role="tablist" aria-label="Analysis type" className="grid grid-cols-2 gap-2 sm:grid-cols-4">{tabs.map((item) => <Button key={item} role="tab" aria-selected={tab === item} variant={tab === item ? "default" : "outline"} onClick={() => { setTab(item); setResult(null); setError(false); }} className="relative min-h-14 px-2">{t(item)}</Button>)}</div>
      <div className="mt-5">{["screenshot", "document"].includes(tab) ? <FileUploadPanel key={tab} kind={tab === "screenshot" ? "screenshot" : "document"} onResult={setResult}/> : <>{tab === "message" ? <Textarea value={value} onChange={(event) => setValue(event.target.value)} aria-label={t("pasteMessage")} placeholder={t("pasteMessage")} className="min-h-40 text-lg"/> : <Input value={value} onChange={(event) => setValue(event.target.value)} aria-label={t("enterUrl")} placeholder="https://example.com" className="h-14 text-lg"/>}<p className="mt-3 font-bold text-critical">⚠️ {t("sensitiveWarning")}</p><div className="mt-5"><p className="mb-2 text-sm font-black uppercase text-muted-foreground">{t("trySample")}</p><div className="flex flex-wrap gap-2">{samples.map(([label, key]) => <Button key={key} variant="secondary" onClick={() => { setTab("message"); setValue(sampleMessages[key] ?? ""); setResult(null); }} className="min-h-11 whitespace-normal text-left">{t(label)}</Button>)}</div></div><Button disabled={loading} onClick={submit} className="mt-6 min-h-14 w-full text-lg">{loading ? <><LoaderCircle className="animate-spin"/>{t("analyzing")}</> : <><Search/>{t("analyzeNow")}</>}</Button>{error && <p role="alert" className="mt-4 border-l-4 border-critical bg-critical-soft p-4 font-bold text-critical">{t("analysisError")}</p>}</>}</div>
    </section>
    {result && <div className="mt-8 space-y-5" aria-live="polite"><RiskScoreCard result={result}/>{"explanation" in result && <section className="content-panel"><h2>{t("explanation")}</h2><p className="mt-3 font-bold">{result.fileName}</p><p className="mt-2">{result.explanation}</p></section>}{result.redFlags.length > 0 && <RedFlagList flags={result.redFlags}/>}{result.redFlags.length > 0 && <HighlightedText text={"extractedText" in result ? result.extractedText : value} flags={result.redFlags}/>}<ActionPanel result={result}/><section className="content-panel"><h2>{t("howVerify")}</h2><ul className="mt-4 space-y-3">{result.verificationSteps.map((step) => <li key={step} className="flex gap-3"><span aria-hidden="true">☐</span><span>{step}</span></li>)}</ul></section><p className="border border-border bg-secondary p-4 text-center font-bold">{t("estimateDisclaimer")}</p></div>}
  </div>;
}