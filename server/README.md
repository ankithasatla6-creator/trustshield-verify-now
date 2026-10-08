# TrustShield AI — Backend

The backend is a small Node + TypeScript service. It scores suspicious messages
and links, turns a report into a numbered case, and checks contact identifiers
against lists.

The frontend keeps talking to `src/lib/api.ts`. When `VITE_API_URL` is set, that
layer calls this service instead of the mock data.

## Run it

```sh
cd server
npm install
npm run dev        # starts on http://localhost:8787 and restarts on file changes
```

Then point the frontend at it:

```sh
# from the project root
echo "VITE_API_URL=http://localhost:8787" > .env.local
npm run dev
```

Without `VITE_API_URL`, the frontend keeps using the mock layer, so the site
still works on its own.

## Check it

```sh
cd server
npm test           # runs the scoring, verify and case checks
npm run typecheck  # type-checks the service
```

## Endpoints

| Method | Path                 | Body                        | Returns                     |
| ------ | -------------------- | --------------------------- | --------------------------- |
| GET    | `/api/health`        | —                           | service status              |
| POST   | `/api/analyze/text`  | `{ "text": "..." }`         | risk score and red flags    |
| POST   | `/api/analyze/url`   | `{ "url": "https://..." }`  | risk score and red flags    |
| POST   | `/api/analyze/file`  | `{ kind, fileName, mimeType, data(base64), note? }` | risk score, red flags, explanation |
| POST   | `/api/verify`        | `{ "identifier": "..." }`   | one of four result labels   |
| POST   | `/api/cases`         | `{ "data": { ... } }`       | stored case with a case ID  |
| GET    | `/api/cases`         | —                           | recent cases                |
| GET    | `/api/cases/:caseId` | —                           | one case                    |

Example:

```sh
curl -s localhost:8787/api/analyze/text \
  -H 'content-type: application/json' \
  -d '{"text":"URGENT: Your bank account will be blocked. Share the OTP to complete KYC immediately."}'
```

## How the score works

`src/scoring.ts` holds the rules. Each rule matches a phrase, explains why that
phrase is a risk, and adds or subtracts points. Positive matches build the
score, phrases like "no payment is required" pull it down. The score maps to:

| Score | Severity    |
| ----- | ----------- |
| 0–29  | `LOW`       |
| 30–59 | `CAUTION`   |
| 60–79 | `HIGH`      |
| 80–99 | `VERY_HIGH` |

Flagged phrases come back exactly as they appeared, so the site can highlight
them in the original message.

`src/verify.ts` answers with only the four allowed labels — Verified, Needs
Verification, Suspicious, Reported Identifier. The trusted and reported lists in
that file are demo data included in this repository, not a live threat feed.

## Settings

Copy `.env.example` to `.env` to change any of these:

| Variable                | Default                                        | Purpose                        |
| ----------------------- | ---------------------------------------------- | ------------------------------ |
| `PORT`                  | `8787`                                         | port the service listens on    |
| `ALLOWED_ORIGINS`       | `http://localhost:8080,http://127.0.0.1:8080`  | browsers allowed to call it    |
| `DATA_FILE`             | `data/cases.json`                              | where cases are stored         |
| `RATE_LIMIT_PER_MINUTE` | `40`                                           | requests allowed per client    |

## Notes for reviewers

- Cases are stored in a local JSON file (`server/data/`, not committed).
  Replacing `src/cases.ts` with a database does not change the API.
- The service returns estimates, never proof. Wording stays careful: "potential
  scam", "high-risk pattern", "verification recommended".
- Nothing here reports anything to the authorities or asks for a password, OTP
  or PIN. The site tells people that too.

## File checks

Screenshots: PNG/JPG/JPEG up to 5 MB. Documents: PDF/DOC/DOCX up to 10 MB. Type and file signature are both checked. Text is read from PDF/DOCX/DOC on the server; screenshots use the optional text the user types (no image text reading yet).
