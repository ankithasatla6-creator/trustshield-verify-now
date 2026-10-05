import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/i18n";

export const Route = createFileRoute("/")({
  head: () => ({ meta: [{ title: "TrustShield AI — Before You Trust It, Verify It" }, { name: "description", content: "AI-powered protection against scams, impersonation and phishing." }, { property: "og:title", content: "TrustShield AI" }, { property: "og:description", content: "Before you trust it, verify it." }, { property: "og:type", content: "website" }, { name: "twitter:card", content: "summary_large_image" }] }),
  component: Index,
});

// IMPORTANT: Replace this placeholder. See ./README.md for routing conventions.
function Index() {
  const { t } = useI18n();
  const scenarios = [{ icon: "🎓", title: "student", text: "studentDesc", to: "/analyze" }, { icon: "👨‍👩‍👧", title: "familyTitle", text: "familyDesc", to: "/family" }, { icon: "💳", title: "paidTitle", text: "paidDesc", to: "/paid" }] as const;
  const flow = [["01", "recognize", "recognizeDesc"], ["02", "verifyStep", "verifyStepDesc"], ["03", "prevent", "preventDesc"], ["04", "respond", "respondDesc"]];
  return (
    <div>
      <section className="border-b border-border bg-primary text-primary-foreground"><div className="mx-auto max-w-6xl px-5 py-12 sm:py-16"><div className="max-w-3xl"><div className="mb-6 inline-flex items-center gap-2 border border-primary-foreground/30 px-3 py-2 text-sm font-bold"><ShieldCheck className="h-5 w-5"/>{t("brand")}</div><h1 className="text-4xl font-black leading-tight sm:text-6xl">{t("tagline")}</h1><p className="mt-5 max-w-2xl text-xl leading-8 text-primary-foreground/80">{t("heroText")}</p><div className="mt-8 grid gap-3 sm:grid-cols-2"><Button asChild className="min-h-14 bg-background text-primary hover:bg-background/90"><Link to="/analyze">{t("analyzeSuspicious")}<ArrowRight/></Link></Button><Button asChild variant="outline" className="min-h-14 border-primary-foreground/50 bg-transparent text-primary-foreground hover:bg-primary-foreground/10 hover:text-primary-foreground"><Link to="/paid">{t("alreadyLost")}</Link></Button></div></div></div></section>
      <section className="mx-auto max-w-6xl px-5 py-12"><div className="grid gap-4 md:grid-cols-3">{scenarios.map((item) => <Link key={item.title} to={item.to} className="group border border-border bg-card p-5 shadow-sm transition-transform focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring md:hover:-translate-y-1"><span className="text-4xl" aria-hidden="true">{item.icon}</span><h2 className="mt-4 text-xl font-black">{t(item.title)}</h2><p className="mt-2 text-muted-foreground">{t(item.text)}</p><ArrowRight className="mt-5 text-primary transition-transform group-hover:translate-x-1"/></Link>)}</div></section>
      <section className="border-y border-border bg-secondary"><div className="mx-auto grid max-w-6xl gap-6 px-5 py-10 sm:grid-cols-2 lg:grid-cols-4">{flow.map(([number, title, text]) => <div key={number} className="grid grid-cols-[auto_1fr] gap-3"><span className="font-black text-primary">{number}</span><div><h2 className="font-black">{t(title)}</h2><p className="mt-1 text-muted-foreground">{t(text)}</p></div></div>)}</div></section>
      <aside className="mx-auto max-w-4xl px-5 py-10 text-center font-bold text-primary"><ShieldCheck className="mx-auto mb-3 h-8 w-8"/>{t("trustNote")}</aside>
    </div>
  );
}
