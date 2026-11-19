# Mbwira

**Multi-organization incident and IT asset management platform.**

*Mbwira* is Kinyarwanda for "tell me": the place where staff tell IT and security what went wrong.

[![CI](https://github.com/uwizey/mbwira/actions/workflows/ci.yml/badge.svg)](https://github.com/uwizey/mbwira/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Django](https://img.shields.io/badge/django-5.2%20LTS-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

> **Status:** under active development. First release (MVP) planned for 20 December 2026.

## The problem

In many organizations, incidents are reported through WhatsApp messages, phone calls and paper.
Reports get buried, nobody clearly owns them, evidence stays on personal phones, and there is
no audit trail to show what happened and what was done.

## The solution

Mbwira gives each organization a private workspace where staff can:

- **Report** security incidents (phishing, malware, lost devices) and IT failures (outages, hardware faults) through one structured form.
- **Triage** each report by type, category and severity, and **assign** it to a named person.
- **Investigate** with comments and evidence attached to the incident.
- **Resolve and close** through a controlled status workflow that requires a written resolution summary.
- **Audit** every important action in an append-only log.
- **Measure** with a manager dashboard (by status, severity and category).

Many organizations share one platform, and **one organization can never see another's data**.

## Features

| Feature | Status |
|---|---|
| Custom user model with email login | Done |
| Login, logout and password change | Done |
| Organizations, memberships and four roles | Planned (Phase 2) |
| Email invitations (expiring, single-use) | Planned (Phase 2) |
| Strict organization isolation, with tests | Planned (Phase 2) |
| Audit log (append-only) | Planned (Phase 2) |
| Asset register | Planned (Phase 3) |
| Incident reporting, triage and assignment | Planned (Phase 3) |
| Status workflow, comments and evidence upload | Planned (Phase 4) |
| Dashboard and audit log viewer | Planned (Phase 4) |
| Hardening, demo data and deployment | Planned (Phase 5) |

## Roles

| Role | Responsibility |
|---|---|
| Organization Admin | Manages users, invitations, roles and assets |
| Security Manager | Oversees operations, reviews statistics and the audit log, can reopen incidents |
| Security Analyst | Triages, investigates and resolves incidents |
| Employee | Reports incidents and sees only their own reports |

The role is stored on the **membership**, not on the user, so one person can hold different roles in different organizations.

## Tech stack

- **Backend:** Python 3.12+, Django 5.2 LTS
- **Frontend:** Django Templates, Bootstrap 5
- **Database:** PostgreSQL 16 (SQLite as a quick local fallback)
- **Config:** django-environ (secrets in environment variables)
- **Static files and serving:** WhiteNoise, Gunicorn
- **Tooling:** Docker Compose, Ruff, coverage, GitHub Actions

## Design decisions

- **Tenant isolation in three layers:** middleware sets the active organization, an organization-scoped manager filters every query, and views return 404 (not 403) for other organizations' objects. The organization is never taken from user input.
- **Role on membership:** supports one user in several organizations with different roles.
- **Business rules in service functions** (status transitions, incident numbering, audit logging), not in views or signals, so they are easy to test and reusable by a future API.
- **Append-only audit log:** the application offers no way to edit or delete audit records.
- **PostgreSQL:** JSON fields, check constraints and partial unique constraints are used to enforce rules in the database.
- **Settings split** into base, development and production, with all secrets read from the environment.

## Getting started

### Option 1: quick start (SQLite, no Docker)

```bash
git clone https://github.com/uwizey/mbwira.git
cd mbwira
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows PowerShell
# source .venv/bin/activate         # macOS / Linux
pip install -r requirements-dev.txt
copy .env.example .env              # macOS / Linux: cp .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open http://127.0.0.1:8000 and log in with your email.

### Option 2: PostgreSQL with Docker

```bash
docker compose up -d
```

Then in `.env`, switch `DATABASE_URL` to the PostgreSQL line shown in `.env.example`, and run
`python manage.py migrate` and `python manage.py createsuperuser`.

## Running the tests

```bash
python manage.py test
```

With coverage:

```bash
coverage run manage.py test
coverage report
```

Lint:

```bash
ruff check .
```

## Project structure

```
mbwira/
  config/              settings (base, development, production), urls, wsgi
  apps/
    accounts/          custom user, authentication
    (core, organizations, assets, incidents, audit, dashboard: coming in later phases)
  templates/  static/
  docs/                design document
  .github/workflows/   CI
  docker-compose.yml  .env.example  requirements.txt
```

## Security and compliance note

Mbwira is designed so that records commonly expected in audits (incident history, triage,
response actions, evidence, asset inventory and audit logs) are produced as a normal part of
daily work, in the spirit of NIST incident-response guidance. It supports record-keeping; it does
not by itself make an organization compliant with NIST or any law.

## Roadmap

After the first release: vulnerability catalogue, task module, REST API, background jobs and
notifications, scanner integration, an AI assistant with human approval, and audit-log
retention and export.

## Author

Built by [@uwizey](https://github.com/uwizey) as a portfolio project demonstrating Django,
PostgreSQL and secure multi-tenant design.

## License

Released under the [MIT License](LICENSE).