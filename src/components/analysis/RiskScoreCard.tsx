import { ShieldAlert } from "lucide-react";
import type { AnalysisResult } from "@/types/analysis";
import { cn } from "@/lib/utils";

const tones = { LOW: "risk-low", CAUTION: "risk-caution", HIGH: "risk-high", VERY_HIGH: "risk-critical" };
export function RiskScoreCard({ result }: { result: AnalysisResult }) {
  return <section aria-label="Risk score" className={cn("border-l-8 bg-card p-5 shadow-sm", tones[result.severity])}>
    <div className="flex items-center gap-3"><ShieldAlert className="h-9 w-9"/><div><p className="text-4xl font-black">{result.riskScore} / 100</p><p className="text-xl font-black">{result.severity.replace("_", " ")} RISK</p></div></div>
    <div className="mt-4 grid gap-2 border-t border-current/20 pt-4 sm:grid-cols-2"><p><span className="font-bold">Category:</span> {result.category}</p><p><span className="font-bold">Confidence:</span> {result.confidence}</p></div>
  </section>;
}