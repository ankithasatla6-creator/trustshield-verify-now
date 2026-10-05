import { Link } from "@tanstack/react-router";
import { Menu, ShieldCheck, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { useI18n } from "@/i18n";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";

export function AppShell({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  const [simple, setSimple] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  useEffect(() => setSimple(window.localStorage.getItem("trustshield-simple") === "true"), []);
  const changeSimple = (checked: boolean) => { setSimple(checked); window.localStorage.setItem("trustshield-simple", String(checked)); };
  const nav = [["/", "home"], ["/analyze", "analyze"], ["/family", "family"], ["/paid", "paid"], ["/verify", "verify"]] as const;
  return (
    <div className={simple ? "simple-mode min-h-screen" : "min-h-screen"}>
      <header className="sticky top-0 z-50 border-b border-border bg-background/95 backdrop-blur">
        <div className="mx-auto grid h-16 max-w-6xl grid-cols-[minmax(0,1fr)_auto] items-center gap-2 px-4">
          <Link to="/" aria-label={t("home")} className="flex min-w-0 items-center gap-2 font-extrabold text-primary"><ShieldCheck className="h-8 w-8 shrink-0"/><span className="truncate">{t("brand")}</span></Link>
          <div className="flex shrink-0 items-center gap-2">
            <label className="hidden items-center gap-2 text-sm font-bold sm:flex"><span>{t("simpleMode")}</span><Switch checked={simple} onCheckedChange={changeSimple} aria-label={t("simpleMode")} /></label>
            <LanguageSwitcher />
            <Button variant="ghost" size="icon" className="h-11 w-11 md:hidden" onClick={() => setMenuOpen(!menuOpen)} aria-label={t("menu")}>{menuOpen ? <X/> : <Menu/>}</Button>
          </div>
          <nav className="hidden items-center justify-end gap-1 md:flex md:col-start-2 md:row-start-1 md:mr-36">
            {nav.map(([to, key]) => <Link key={to} to={to} activeProps={{ className: "bg-secondary text-primary" }} className="rounded-md px-3 py-2 text-sm font-bold text-muted-foreground hover:text-foreground">{t(key)}</Link>)}
          </nav>
        </div>
        {menuOpen && <nav className="border-t border-border bg-background px-4 py-3 md:hidden"><label className="mb-3 flex h-12 items-center justify-between font-bold"><span>{t("simpleMode")}</span><Switch checked={simple} onCheckedChange={changeSimple} aria-label={t("simpleMode")} /></label>{nav.map(([to, key]) => <Link key={to} to={to} onClick={() => setMenuOpen(false)} className="flex min-h-12 items-center border-t border-border font-bold text-foreground">{t(key)}</Link>)}</nav>}
      </header>
      <main>{children}</main>
    </div>
  );
}