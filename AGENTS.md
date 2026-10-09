<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

- Keep mock service calls behind `src/lib/api.ts` so a future `VITE_API_URL` backend can replace data without changing page components.
- Keep all visible product copy behind the i18n helper; English is the fallback while Telugu and Hindi initially cover landing and emergency flows.
- Keep identifier presentation signals in a browser-safe helper separate from API verdicts so explanations cannot silently change verification labels or other analysis flows.
