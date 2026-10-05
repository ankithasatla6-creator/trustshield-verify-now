import { useState } from "react";
import type { AnalysisResult } from "@/types/analysis";
export function HighlightedText({ text, flags }: { text: string; flags: AnalysisResult["redFlags"] }) {
  const [selected, setSelected] = useState<string | null>(null);
  const regex = new RegExp(`(${flags.map((flag) => flag.text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "gi");
  return <section className="content-panel"><h2>Suspicious phrases</h2><p className="mt-4 leading-8">{text.split(regex).map((part, index) => { const flag = flags.find((item) => item.text.toLowerCase() === part.toLowerCase()); return flag ? <button key={`${part}-${index}`} type="button" onClick={() => setSelected(flag.reason)} className="rounded-sm bg-warning-soft px-1 font-bold text-warning underline decoration-2 underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">{part}</button> : part; })}</p>{selected && <p role="status" className="mt-4 border-l-4 border-warning bg-warning-soft p-3 font-medium">{selected}</p>}</section>;
}