import { useI18n, type Language } from "@/i18n";

export function LanguageSwitcher() {
  const { language, setLanguage, t } = useI18n();
  return (
    <label className="flex shrink-0 items-center gap-2">
      <span className="sr-only">{t("language")}</span>
      <select aria-label={t("language")} value={language} onChange={(event) => setLanguage(event.target.value as Language)} className="h-11 rounded-md border border-input bg-background px-2 text-sm font-bold text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
        <option value="en">EN</option><option value="te">తెలుగు</option><option value="hi">हिन्दी</option>
      </select>
    </label>
  );
}