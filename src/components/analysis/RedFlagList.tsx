import type { AnalysisResult } from "@/types/analysis";
const icons = { high: "🔴", medium: "🟠", low: "🟡" };
export function RedFlagList({ flags }: { flags: AnalysisResult["redFlags"] }) {
  return <section className="content-panel"><h2>Why this score</h2><ul className="mt-4 space-y-4">{flags.map((flag) => <li key={flag.text} className="grid grid-cols-[auto_1fr] gap-3"><span aria-label={`${flag.weight} concern`}>{icons[flag.weight]}</span><div><p className="font-bold">{flag.text}</p><p className="text-muted-foreground">{flag.reason}</p></div></li>)}</ul></section>;
}