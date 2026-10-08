import { FileText, FileUp, ImageIcon, LoaderCircle, Search, X } from "lucide-react";
import { useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { useI18n } from "@/i18n";
import { analyzeFile, FILE_LIMITS, validateFile } from "@/lib/api";
import type { FileAnalysisResult, FileKind } from "@/types/analysis";

const errorKeys: Record<string, string> = {
  "too-large": "fileTooLarge",
  "unsupported-type": "fileWrongType",
  "no-text": "fileNoText",
  "no-file": "noFile",
};

export function FileUploadPanel({ kind, onResult }: { kind: FileKind; onResult: (result: FileAnalysisResult | null) => void }) {
  const { t } = useI18n();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function pick(next: File | undefined) {
    onResult(null);
    setError(null);
    if (preview) URL.revokeObjectURL(preview);
    setPreview(null);
    if (!next) return setFile(null);
    const invalid = validateFile(kind, next);
    if (invalid) {
      setFile(null);
      setError(invalid);
      return;
    }
    setFile(next);
    if (kind === "screenshot") setPreview(URL.createObjectURL(next));
  }

  async function submit() {
    if (!file) return setError("no-file");
    setLoading(true);
    setError(null);
    onResult(null);
    try {
      onResult(await analyzeFile(kind, file, note));
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
    } finally {
      setLoading(false);
    }
  }

  const Icon = kind === "screenshot" ? ImageIcon : FileText;
  return (
    <div>
      <input ref={inputRef} type="file" accept={FILE_LIMITS[kind].accept} className="sr-only" aria-label={t(kind === "screenshot" ? "uploadScreenshot" : "uploadDocument")} onChange={(e) => pick(e.target.files?.[0])} />
      {!file ? (
        <button type="button" onClick={() => inputRef.current?.click()} onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); pick(e.dataTransfer.files[0]); }} className="grid min-h-56 w-full place-items-center border-2 border-dashed border-border bg-secondary p-6 text-center focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          <span><FileUp className="mx-auto h-10 w-10 text-primary" /><span className="mt-3 block font-bold">{t(kind === "screenshot" ? "uploadScreenshot" : "uploadDocument")}</span><span className="mt-3 inline-flex min-h-12 items-center rounded-md bg-primary px-5 font-bold text-primary-foreground">{t("chooseFile")}</span></span>
        </button>
      ) : (
        <div className="border border-border bg-secondary p-4">
          <p className="text-sm font-black uppercase text-muted-foreground">{t("selectedFile")}</p>
          <div className="mt-2 flex items-center gap-3">
            {preview ? <img src={preview} alt="" className="h-16 w-16 rounded object-cover" /> : <Icon className="h-10 w-10 shrink-0 text-primary" />}
            <div className="min-w-0 flex-1"><p className="truncate font-bold">{file.name}</p><p className="text-sm text-muted-foreground">{(file.size / 1024).toFixed(0)} KB</p></div>
            <Button variant="outline" onClick={() => inputRef.current?.click()} className="min-h-12">{t("changeFile")}</Button>
            <Button variant="ghost" size="icon" aria-label={t("removeFile")} onClick={() => { if (inputRef.current) inputRef.current.value = ""; pick(undefined); }}><X /></Button>
          </div>
        </div>
      )}
      <Textarea value={note} onChange={(e) => setNote(e.target.value)} aria-label={t(kind === "screenshot" ? "screenshotNote" : "documentNote")} placeholder={t(kind === "screenshot" ? "screenshotNote" : "documentNote")} className="mt-4 min-h-24 text-lg" />
      <p className="mt-3 font-bold text-critical">⚠️ {t("sensitiveWarning")}</p>
      <Button disabled={loading} onClick={submit} className="mt-6 min-h-14 w-full text-lg">{loading ? <><LoaderCircle className="animate-spin" />{t("analyzing")}</> : <><Search />{t("analyzeFile")}</>}</Button>
      {error && <p role="alert" className="mt-4 border-l-4 border-critical bg-critical-soft p-4 font-bold text-critical">{t(errorKeys[error] ?? "analysisError")}</p>}
    </div>
  );
}
