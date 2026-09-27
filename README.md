# Incident-Breach-Response

[![Live Demo](https://img.shields.io/badge/Live_Demo-incident--breach--response.vercel.app-000000?style=flat&logo=vercel&logoColor=white)](https://incident-breach-response.vercel.app)
[![GitHub](https://img.shields.io/badge/GitHub-GugaValenca-181717?style=flat&logo=github&logoColor=white)](https://github.com/GugaValenca)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-gugavalenca-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/gugavalenca/)

A security incident and breach response tracker: log an incident, record
which data categories, systems and processing activities it affects and
how many people in which jurisdictions, and the tool works out which
notifications LGPD, GDPR and California law require, to whom, and by
when — with a live countdown from the discovery date, a response
checklist with owners, a timeline, and an exportable PDF incident report.

This is Project 4 of the portfolio and closes the loop on the other
three, all built around the same fictional NimbusCart e-commerce company:
[Project 1](https://github.com/GugaValenca/lgpd-gdpr-ccpa-comparative-analysis)
compares the legal frameworks,
[Project 2 (Data-Mapping-ROPA)](https://github.com/GugaValenca/data-mapping-ropa)
records the processing activities already running (this project reuses
its data categories and processing activities, so an incident points at
the same ROPA entries), and
[Project 3 (DPIA)](https://github.com/GugaValenca/dpia-privacy-impact-assessment)
assesses a new activity before it launches. This one covers what happens
when something goes wrong anyway.

## The problem it solves

In the first hours of a breach, a privacy team has to answer the same
questions every time — *which laws are triggered? who do we tell? how
long do we have?* — under pressure and with incomplete facts. The answers
depend on details that change as the investigation develops (a head count
crosses a threshold, encryption turns out to have been bypassed), and the
clocks run differently in each jurisdiction: GDPR counts hours, the ANPD
counts business days, California counts calendar days, and California's
Attorney General deadline doesn't start until the consumer notice goes out.

This tool keeps the facts in one place and re-evaluates the obligations
from them on every page view, so updating a fact can never leave a stale
verdict behind — and it shows *why* each obligation applies, not just
whether it does.

## What it does

- **Incident record** — discovery date (the clock start), incident type,
  containment status, affected data categories, systems and ROPA
  processing activities, affected individuals per jurisdiction, and the
  documented judgment calls the legal tests turn on (risk to individuals,
  encryption, large scale, and so on).
- **Notification obligations per framework** — each requirement shows its
  recipient, citation, deadline, status (pending / overdue / sent / no
  fixed deadline / not applicable) with a countdown, and the reasons it
  applies or doesn't (e.g. *"RCIS Art. 5 criteria met: system
  authentication data (IV); large-scale data (VI)"*). Recording a notice
  as sent stops its clock, flags it if it went out late, logs it to the
  timeline, and — for California's AG copy — re-anchors the dependent
  deadline on the actual send date.
- **Severity assessment** — a simplified internal triage score (what data,
  how many people, containment, deliberate cause, encryption), clearly
  labelled as **not an official classification system** and kept
  separate from the legal tests.
- **Response checklist** — 14 default tasks across triage, containment,
  assessment, notification, recovery and review, each with an owner and a
  status; teams can add their own.
- **Timeline** — the chronology GDPR Art. 33(5) and ANPD RCIS Art. 10
  expect a controller to be able to produce.
- **Dashboard** — every incident with severity, containment, head count,
  frameworks triggered and the next deadline; filterable by text,
  containment, severity, jurisdiction and framework.
- **PDF export** — the full incident report (facts, scope, severity,
  obligations with reasons, checklist, timeline) via ReportLab.
- **Legal sources page** — every requirement with its source link,
  verification date and notes; unverified content is flagged, not hidden.

## Legal content — how it was verified

Every deadline, threshold, authority and citation lives in one place,
`LEGAL_REQUIREMENTS` in `incidents/management/commands/seed_incidents.py`,
and each one was checked against a primary or regulatory source on
**2026-09-26**, following Project 1's content policy: verified rows carry
`is_verified=True`, a `source_url` and notes on exactly what was checked;
anything not fully confirmed is `is_verified=False` with a
`TODO: VERIFY ...` note. The decision logic never restates a deadline —
it reads them from these rows.

| Requirement | Recipient | Deadline | Source | Status |
|---|---|---|---|---|
| LGPD Art. 48 + Res. CD/ANPD nº 15/2024, Arts. 5-6 | ANPD (electronic form) | 3 business days from knowledge that the incident affected personal data (doubled for small-scale agents) | planalto.gov.br, in.gov.br (Diário Oficial) | Verified |
| LGPD Art. 48 + Res. 15/2024, Art. 9 | Affected data subjects | 3 business days (doubled for small-scale agents) | in.gov.br | Verified |
| Res. 15/2024, Art. 10 | Internal incident record | Keep ≥ 5 years, including incidents not communicated | in.gov.br | Verified |
| GDPR Art. 33(1), (3)-(4); EDPB Guidelines 9/2022 paras. 72-73 | Supervisory authority — for a non-EU controller, each authority where affected data subjects reside | Without undue delay, where feasible ≤ 72 hours after becoming aware | eur-lex.europa.eu, edpb.europa.eu | Verified |
| GDPR Art. 34 | Affected data subjects (if high risk) | Without undue delay (no fixed number) | eur-lex.europa.eu | Verified |
| GDPR Art. 33(5) | Internal breach record | Ongoing | eur-lex.europa.eu | Verified |
| Cal. Civ. Code § 1798.82(a) | Affected California residents | 30 calendar days of discovery or notification (as amended by SB 446, eff. Jan. 1, 2026) | leginfo.legislature.ca.gov | Verified |
| Cal. Civ. Code § 1798.82(f) | California Attorney General (> 500 residents) | 15 calendar days of notifying consumers | leginfo.legislature.ca.gov | Verified |
| Cal. Civ. Code § 1798.150 (CCPA/CPRA) | No notice — litigation exposure flag | — | leginfo.legislature.ca.gov | **Unverified** (see below) |

**Still to verify, or simplified on purpose** — consolidated here for
anyone auditing this repo:

| Location | What |
|---|---|
| `seed_incidents.py` (`ccpa-private-action`) | `TODO: VERIFY` — § 1798.150 incorporates § 1798.81.5(d)(1)(A)'s definition of personal information, which could only be read in summary, not quoted, on 2026-09-26. The tool approximates it with the same flag used for § 1798.82(h). |
| `incidents/obligations.py` | Each rule's docstring states its simplification: LGPD's "may significantly affect" is read from the team's documented risk level; only GDPR Art. 34(3)(a) (encryption) is evaluated, not (b)/(c); California's "acquired by an unauthorized person" is assumed for every recorded incident. |
| Scope | Other US states' breach laws, sector-specific regimes and contractual notice duties to customers/partners are not evaluated. |

**How LGPD business days are counted: a documented interpretation.** The
3-business-day figure is verified, but Res. CD/ANPD nº 15/2024 doesn't say
*how* to count business days, and neither does the ANPD's
incident-communication page. The tool fills that gap by analogy with the
closest rules, both checked on 2026-09-26:
[Res. CD/ANPD nº 1/2021, Art. 8](https://www.gov.br/anpd/pt-br/acesso-a-informacao/institucional/atos-normativos/regulamentacoes_anpd/resolucao-cd-anpd-no1-2021)
(business days, start day excluded, end day included, extension when the
ANPD's headquarters has no working hours on the last day) and
[Lei 9.784/1999, Art. 66](https://www.planalto.gov.br/ccivil_03/leis/l9784.htm)
(same start/end rule). Art. 8 governs Res. 1/2021's own deadlines, so it's
applied here by analogy, supported by the ANPD processing an incident
communication as an administrative case. On the points the analogy leaves
open, the tool takes the conservative reading: public holidays aren't
skipped and days end at 23:59 UTC (20:59 in Brasília), so the date shown is
never later than the analogy gives. The one assumption that cuts the other
way is the start-day exclusion itself, which both rules state. The
interpretation is labelled as such in `incidents/deadlines.py`, in the
requirements' verification notes, and next to every LGPD deadline in the
app and the PDF.

Every screen and PDF carries the disclaimer that this is a
portfolio/demonstration tool about a fictional company and not legal
advice.

## Design decisions worth explaining

- **Facts vs. law vs. logic.** Incident facts are entered by the team;
  legal content is seeded data with provenance; applicability is code —
  one small predicate per requirement code in `incidents/obligations.py`,
  each reading only an `IncidentFacts` snapshot. That split is what makes
  the legal content auditable (it's all in one list with sources) and the
  logic testable (pure functions, no database).
- **Judgment calls are recorded, not computed.** Whether a breach is
  "likely to result in a high risk" is the controller's documented
  decision. The tool asks for it explicitly instead of inferring it from
  the severity score.
- **Nothing computed is stored.** Severity and obligations are recomputed
  on every request, so there's no cached verdict to go stale when a fact
  changes.
- **Deadline arithmetic is isolated** in `incidents/deadlines.py` — the
  part of the app where a bug would do the most harm, so it has its own
  tests for weekends, start-day exclusion and end-of-day boundaries.

## Built with

- **Backend**: Django 6 (models, admin, ModelForms, function-based
  views, `prefetch_related` so the dashboard stays at a fixed number of
  queries, built-in Content-Security-Policy support) — the same stack as
  Projects 1-3
- **Frontend**: Django templates, plain CSS (light/dark aware, palette
  shared with Projects 2 and 3), a few lines of vanilla JS
- **PDF generation**: [ReportLab](https://www.reportlab.com/), matching
  Projects 2 and 3
- **Tests**: Django's built-in test runner (`python manage.py test incidents`)
- **Tooling**: black, isort, ruff and mypy with django-stubs, configured in
  `pyproject.toml` as in Projects 2 and 3; bandit and pip-audit for
  security checks
- **Deployment**: [Vercel](https://vercel.com) (Python/WSGI runtime),
  Postgres in production via `dj-database-url` (SQLite locally), static
  files via [WhiteNoise](https://whitenoise.readthedocs.io/)

## Running it locally

```bash
# 1. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up the database
python manage.py migrate

# 4. Load the legal requirements, NimbusCart reference data and 4 sample incidents
python manage.py seed_incidents

# 5. Create an admin login (there is no preset admin account in this repo)
python manage.py createsuperuser

# 6. Run the server
python manage.py runserver
```

Then visit:

- **Dashboard**: <http://127.0.0.1:8000/>
- **Log an incident**: <http://127.0.0.1:8000/incidents/new/>
- **Legal sources**: <http://127.0.0.1:8000/legal-sources/>
- **About**: <http://127.0.0.1:8000/about/>
- **Admin**: <http://127.0.0.1:8000/admin/>

The sample incidents are dated relative to when the seed runs, so the
countdowns are live: one intrusion with the GDPR 72-hour clock running,
one ransomware incident with an overdue LGPD notice, one vendor incident
already notified, and one encrypted-laptop theft that triggers nothing.
Re-run `seed_incidents` to reset the clocks (`--keep` adds to existing
data instead of clearing it).

## Testing

```bash
python manage.py test incidents
```

90 tests cover: deadline arithmetic (weekend crossing, start-day
exclusion, end-of-day boundaries, countdown labels); each framework's
applicability rule, including the edges that matter legally (RCIS
criteria are cumulative with risk; California has no risk-of-harm test;
the AG threshold is *more than* 500; encryption exceptions and their loss
when the key is compromised); small-agent deadline doubling; the AG
deadline re-anchoring on the actual consumer-notice date; the severity
model's weights and boundaries; the seed data honoring the verification
policy (every verified row has a source and date, every unverified row a
TODO, every source is a primary/regulatory domain); the dashboard filters,
forms, validation and detail-page actions through real requests; and the
PDF export producing complete, disclaimer-carrying, markup-safe output;
and the security hardening described below (rate limits, client-IP
handling, the shared rate-limit cache in production, CSP and security
headers, input ceilings, reference numbering
after deletions, and the settings refusing to start insecurely).

The suite passes on both SQLite and PostgreSQL 16:

```bash
DATABASE_URL="postgres://user:password@localhost:5432/dbname" python manage.py test incidents
```

Static and security checks:

```bash
pip install -r requirements-dev.txt bandit
black --check . && isort --check . && ruff check . && mypy incidents config api
bandit -r incidents config api -x incidents/tests.py,incidents/migrations
pip-audit -r requirements.txt
```

## Project structure

```
api/index.py                   WSGI entrypoint Vercel's Python runtime routes into
vercel.json                     Vercel build/route config
config/                        Django project settings & root URLs
incidents/                      The incident-response app
  models.py                     DataCategory, ProcessingActivity, System, LegalRequirement,
                                  Incident, JurisdictionImpact, TimelineEvent,
                                  ChecklistItem, NotificationRecord
  obligations.py                Which requirements apply, and by when (pure, tested)
  deadlines.py                  Deadline arithmetic and countdowns (pure, tested)
  severity.py                   Internal severity model (pure, tested)
  checklist.py                  Default response checklist
  forms.py                      Incident form and detail-page action forms
  views.py                      Dashboard, detail, create/edit, actions, export
  exports.py                    PDF incident report
  throttling.py                 Which client IP the rate limits count against
  admin.py                      Django admin configuration
  tests.py                      90 tests
  management/commands/
    seed_incidents.py            Verified legal requirements + NimbusCart sample data
  templates/                     Page templates, plus the 403/404/500 error pages
static/                          CSS (shared palette) and JS
.env.example                     Environment variables this app reads (copy to .env)
```

## Security notes

- **Configuration fails safe.** `SECRET_KEY`, `DEBUG` and `ALLOWED_HOSTS`
  come from environment variables (`config/settings.py`, `.env.example`).
  On Vercel, `DEBUG` defaults to off, and with `DEBUG` off the app refuses
  to start without `DJANGO_SECRET_KEY` rather than falling back to the
  development key published in this repo. `manage.py check --deploy`
  reports no issues.
- **Transport and browser protections.** With `DEBUG` off: HTTPS redirect,
  HSTS (1 year, preload), secure session and CSRF cookies. On every
  response: a strict Content-Security-Policy (`default-src 'self'`, no
  inline scripts or styles, `frame-ancestors 'none'`),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin` and `Cross-Origin-Opener-Policy`.
- **Input handling.** CSRF protection on every form; detail-page actions
  are POST-only; every value goes through a Django form before it's saved.
  Date and encryption rules live on the models, so the admin enforces them
  too. Free-text fields are capped at 5,000 characters and head counts at
  one billion, so oversized input is a form error, never a database error.
  Templates auto-escape everything (no `|safe` / `mark_safe`), the PDF
  export escapes ReportLab markup, and the ORM is used throughout (no raw
  SQL).
- **Rate limiting.** Each visitor gets 30 writes and 10 PDF exports per
  minute; the admin login allows 5 attempts per minute. On Vercel the
  visitor is identified by `X-Real-IP`, which Vercel overwrites with the
  client's address so it can't be spoofed; elsewhere that header is
  ignored (`incidents/throttling.py`). In production the counters live in
  a Postgres cache table shared by every serverless instance. Per-process
  memory would give each instance its own counters, which in practice
  meant no limit at all on the live site (found and fixed during
  deployment testing).
- **Checked with tools.** bandit reports no issues (two false positives are
  annotated in place with the reason), and pip-audit finds no known
  vulnerabilities in the dependencies. The repo contains no secrets.
- **Like Project 3's wizard, the public pages are open for demo purposes**:
  anyone with the URL can log incidents and update checklists. A real
  incident register holds confidential information and would sit behind
  authentication (e.g. `login_required` on every view), deliberately left
  out here so the demo can be tried without an account.
- **Known limits of the demo setup.** The database cache increments
  counters with a read-then-write, so two requests arriving in the same
  instant can be counted once: the limits are approximate, not exact.
  Dependencies are version ranges, not a lock file, matching Projects 2
  and 3.
- There is no admin account in this repo or its seed; `db.sqlite3` is
  git-ignored and all sample data lives in the seed command.

## Deployment (Vercel)

Set up exactly like Projects 2 and 3: `vercel.json` + `api/index.py`
route every request into the Django WSGI app, and `config/settings.py`
switches from SQLite to Postgres whenever `DATABASE_URL`/`POSTGRES_URL`
is present.

1. **Connect the repo**: Vercel dashboard → *Add New… → Project* → import
   the repository from GitHub.
2. **Add a Postgres database**: Project → *Storage* → *Create Database* →
   Postgres (injects `POSTGRES_URL` automatically).
3. **Set environment variables** (Project → *Settings → Environment
   Variables*): `DJANGO_SECRET_KEY` (see `.env.example` for the one-liner
   that generates one; the app won't start without it) and
   `DJANGO_ALLOWED_HOSTS` only for a custom domain. `DJANGO_DEBUG` already
   defaults to `False` on Vercel.
4. **Run migrations and seed against the production database** (Vercel's
   build doesn't do this for you):
   ```bash
   DATABASE_URL="<value from Vercel's Storage tab>" python manage.py migrate
   DATABASE_URL="<same value>" python manage.py createcachetable   # rate-limit counters
   DATABASE_URL="<same value>" python manage.py seed_incidents
   DATABASE_URL="<same value>" python manage.py createsuperuser
   ```
5. **Deploy**: `vercel --prod`, or push to the connected branch.

After re-verifying legal content, update only the requirements in the
production database, leaving incidents untouched:

```bash
DATABASE_URL="<same value>" python manage.py seed_incidents --requirements-only
```

Live at [incident-breach-response.vercel.app](https://incident-breach-response.vercel.app),
on a Neon Postgres database provisioned through Vercel's marketplace
integration, migrated and seeded. Verified against the live deployment:
every page and PDF export, the CSRF-protected incident form, the HTTP →
HTTPS redirect, the security headers and the rate limits. Also verified
locally on SQLite and PostgreSQL 16 with the full test suite.

## About the author

Gustavo Valença is a Brazilian-trained lawyer with legal team leadership
experience, working across Python/Django development and data privacy
law (LGPD, GDPR, CCPA). This project turns the first hours of a breach —
the part of privacy law with the least room for error — into a
structured, tested Django application, with every legal deadline traced
back to its primary source.

This is **Project 4** of a four-project portfolio:

1. [LGPD-GDPR-CCPA-Comparative-Analysis](https://github.com/GugaValenca/lgpd-gdpr-ccpa-comparative-analysis) — comparing the underlying legal frameworks side by side.
2. [Data-Mapping-ROPA](https://github.com/GugaValenca/data-mapping-ropa) — recording processing activities already running.
3. [DPIA-Privacy-Impact-Assessment](https://github.com/GugaValenca/dpia-privacy-impact-assessment) — assessing a new one before it launches.
4. **Incident-Breach-Response** (this project) — responding when something goes wrong.

[![GitHub](https://img.shields.io/badge/GitHub-GugaValenca-181717?style=flat&logo=github&logoColor=white)](https://github.com/GugaValenca)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-gugavalenca-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/gugavalenca/)
