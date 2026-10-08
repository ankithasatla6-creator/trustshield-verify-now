# TrustShield AI Verify

Build the complete frontend for "TrustShield AI", a mobile-first AI scam protection web app for a hackathon (AI + Cybersecurity). Tagline: "Before you trust it, verify it."
TECH: React + TypeScript + Tailwind + React Router. No backend yet. Use mock data behind one API layer.
DESIGN:
- Trustworthy, clean, professional. Navy (#0F2A4A) as primary, white background, soft gray cards
- Risk colors: green #16A34A (0-29), yellow #CA8A04 (30-59), orange #EA580C (60-79), red #DC2626 (80-100)
- No neon, no hacker/terminal visuals, no heavy gradients, minimal animation
- Mobile-first. Base text 18px. Buttons at least 56px tall. High contrast
- Sticky top bar: logo, "Simple Mode" toggle, language dropdown (EN / తెలుగు / हिन्दी)
PAGES:
1. "/" Landing
- Hero: "Before you trust it, verify it." Subtext: "AI-powered protection against scams, impersonation, phishing, fake opportunities and digital fraud."
- Primary button "Analyze Something Suspicious" -> /analyze. Secondary "I Already Lost Money" -> /paid
- Three scenario cards: 🎓 Student / Job Scam ("Someone offered me a job or internship") -> /analyze, 👨‍👩‍👧 Family Emergency Scam ("Someone says they are my family member") -> /family, 💳 Already Paid ("I already sent money") -> /paid
- Flow strip: RECOGNIZE → VERIFY → PREVENT → RESPOND, with one short line under each
- Trust note: "TrustShield is a safety assistant, not law enforcement. We never ask for passwords or OTPs."
2. "/analyze" Analysis dashboard
- Tabs: Message | URL | Screenshot | Document. Message and URL work. Screenshot and Document show an upload box with a "Coming soon" badge
- Warning under input: "Do not paste passwords, OTPs, PINs or card CVV."
- "Try a sample" buttons: Fake Internship, Fake Bank Support, Family Emergency, Recovery Scam, Legitimate Internship, Delivery Notification
- Analyze button with loading state and a friendly error state
- RESULT (below the input):
  a) Big score card: "91 / 100 VERY HIGH RISK" in the risk color, plus category and a confidence label
  b) "Why this score": list of reasons with 🔴 / 🟠 / 🟡 icons
  c) The user's original text with suspicious phrases highlighted. Tapping a highlight shows its reason
  d) "What should I do?" numbered action panel. If paymentWarning is true, show a red banner at top: "Do not pay yet"
  e) "How to verify" checklist
  f) Disclaimer: "This is an AI estimate, not proof. Verification recommended."
- Use careful wording only: "Potential scam", "High-risk pattern", "Verification recommended". Never "criminal" or "fraudster"
3. "/family" Family emergency flow
- Step 1: "Someone says your family member is in trouble. What happened?" Big tappable options: 📞 Emergency call, 🎥 Video call, 🎙️ Voice message, 💬 WhatsApp message, 📸 Photo/video sent, 💰 Money requested (multi-select)
- Step 2: full-screen red "🛑 STOP. Don't send money yet."
- Step 3: four huge buttons, each opens a short guidance card: 📞 Call them directly on a number you already know, 👥 Ask another family member, 🔐 Ask a private question only they know, 💳 Check who the payment goes to
- Note: "AI-generated video or voice cannot always be identified by looking at it. Verify through another channel."
4. "/paid" Already paid: Build My Case
- Multi-step form: what happened, date/time, amount, payment method, transaction ID/UTR, recipient/UPI ID, phone, email, website, social account, organization/person name, promised service, what was delivered, evidence notes
- Output: "CASE #TS-2026-001" summary card with a timeline, Copy and Download (.txt) buttons
- "Official Help" section: National Cyber Crime Reporting Portal (https://cybercrime.gov.in) and the 1930 helpline with tap-to-call. Text: "You stay in control. TrustShield does not report anything for you."
- "Recovery scam warning" box: "If someone offers to recover your money for a fee, do not pay."
5. "/verify" Verify Before You Trust
- Input for phone/email/website/UPI/social URL/organization. Result label only from: Verified, Needs Verification, Suspicious, Reported Identifier. Add "Coming soon" note for live checks
SIMPLE MODE (global toggle, saved in localStorage):
- Larger text, big icon buttons, max 1 sentence per step
- Action words: 🛑 STOP, 📞 CALL THEM DIRECTLY, 👨‍👩‍👧 ASK FAMILY, 💳 CHECK PAYMENT, ✅ VERIFY FIRST
I18N:
- src/i18n/en.ts, te.ts, hi.ts with the same keys. Use a t("key") helper. No hardcoded UI text in components
- Add real Telugu and Hindi for the landing page and STOP flow. Fall back to English for missing keys
API LAYER (src/lib/api.ts):
- analyzeText(text), analyzeUrl(url), buildCase(data)
- For now return mock data from src/lib/mockData.ts with the sample scenarios above
- Result type in src/types/analysis.ts:
{ riskScore: number; severity: "LOW"|"CAUTION"|"HIGH"|"VERY_HIGH"; category: string; confidence: "low"|"moderate"|"high"; redFlags: {text: string; reason: string; weight: "high"|"medium"|"low"}[]; recommendedActions: string[]; verificationSteps: string[]; paymentWarning: boolean }
- Later I will replace mock calls with a real backend URL from an env variable VITE_API_URL
RULES:
- Every button must work or show a "Coming soon" badge
- Reusable components: RiskScoreCard, RedFlagList, HighlightedText, ActionPanel, StopScreen, LanguageSwitcher
- Accessible: aria-labels, keyboard focus, color is never the only signal
- Test at 360px width first

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://trustshield-verify-now.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/8ab8921f-641b-4323-88a8-cb551dc0c787).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```

## Backend (optional)

The frontend runs on its own using the mock data in `src/lib/mockData.ts`. A real API lives in [`server/`](server/README.md) — Node + TypeScript + Express — and implements the same calls the frontend already makes.

Run it:

```sh
cd server
npm i
cp .env.example .env
npm run dev        # serves http://localhost:8787
npm test           # selftest: scoring, case ids, verify labels
```

Then tell the frontend to use it. Copy `.env.example` to `.env.local` in the project root and restart `npm run dev`:

```sh
VITE_API_URL=http://localhost:8787
```

With `VITE_API_URL` set, every request goes to the API; without it, the app falls back to mock data, so the preview keeps working.

| Method | Endpoint | What it does |
| --- | --- | --- |
| GET | `/api/health` | Liveness check |
| POST | `/api/analyze/text` | Scores a pasted message |
| POST | `/api/analyze/url` | Scores a website address |
| POST | `/api/verify` | Labels an identifier: Verified / Needs Verification / Suspicious / Reported Identifier |
| POST | `/api/cases` | Builds a case, returns `CASE #TS-2026-001` |
| GET | `/api/cases` · `/api/cases/:caseId` | Lists or reads stored cases (JSON file store) |
