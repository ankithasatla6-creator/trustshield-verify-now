import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { en } from "./en";
import { hi } from "./hi";
import { te } from "./te";

export type Language = "en" | "te" | "hi";
const dictionaries: Record<Language, Record<string, string>> = { en, te, hi };

type I18nValue = { language: Language; setLanguage: (language: Language) => void; t: (key: string) => string };
const I18nContext = createContext<I18nValue>({ language: "en", setLanguage: () => undefined, t: (key) => key });

export function I18nProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>("en");
  useEffect(() => {
    const saved = window.localStorage.getItem("trustshield-language") as Language | null;
    if (saved && dictionaries[saved]) setLanguageState(saved);
  }, []);
  const setLanguage = (next: Language) => { setLanguageState(next); window.localStorage.setItem("trustshield-language", next); };
  const t = (key: string) => dictionaries[language][key] ?? dictionaries.en[key] ?? key;
  return <I18nContext.Provider value={{ language, setLanguage, t }}>{children}</I18nContext.Provider>;
}

export const useI18n = () => useContext(I18nContext);