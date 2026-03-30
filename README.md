# SecureVault Password Manager

Work in progress, but usable.

SecureVault is a full-stack password manager prototype focused on encrypted vault storage, strong auth flows, and practical security hardening.

## Current Status

- Project stage: Mid-to-late MVP
- Backend: Auth, MFA, vault CRUD, JWT protection, request hardening
- Frontend: Register/login flows, encrypted vault UX, session checks
- Infrastructure: Docker Compose stack for local development
- Testing: Security and integration tests in backend

This README prioritizes getting you running quickly while the project is still evolving.

## Tech Stack

- Backend: Go, Chi router, GORM, PostgreSQL, JWT, TOTP MFA
- Frontend: React, TypeScript, Vite, Axios
- API Contract: OpenAPI (with generated server bindings)
- Local Infra: Docker Compose

## Repository Layout

```text
api-specs/                 OpenAPI contract
backend/                   Go API + auth + vault + MFA + tests
frontend/password_manager/ React app
deployments/               Docker/K8s deployment scaffolding
scripts/                   Utility scripts
docker-compose.yml         Local full-stack startup
PROJECT_PROGRESS.md        Detailed implementation snapshot
```

## Implemented Features

### Authentication

- User registration
- User login
- Session validation endpoint
- JWT-based protected routes
- Login abuse mitigation (rate limit / lockout behavior)

### Multi-Factor Authentication

- MFA status endpoint
- MFA setup start + confirm
- MFA disable
- MFA login verification flow

### Vault

- Add encrypted secrets
- Fetch user vault entries
- Delete vault entries
- Server-side schema checks to prevent legacy/plaintext rows

### Security-Oriented Behaviors

- Strict JSON decode behavior (single object, unknown fields rejected)
- Content-Type checks for JSON endpoints
- Request size limits
- Legacy password hash enforcement checks
- Optional hardening flags (for example HSTS toggle)

## API Endpoints (Current)

### Public

- POST /api/v1/auth/register
- POST /api/v1/auth/login
- POST /api/v1/auth/mfa/verify-login

### JWT Protected

- GET /api/v1/auth/session
- GET /api/v1/auth/mfa/status
- POST /api/v1/auth/mfa/setup/start
- POST /api/v1/auth/mfa/setup/confirm
- POST /api/v1/auth/mfa/disable
- GET /api/v1/vault
- POST /api/v1/vault
- DELETE /api/v1/vault/{id}

## Prerequisites

Choose one setup path:

- Docker path: Docker + Docker Compose
- Local path: Go 1.25+, Node 20+, npm, PostgreSQL 15+

## Environment Variables

Create a root .env file (used by Docker Compose and backend).

Required:

- POSTGRES_USER
- POSTGRES_PASSWORD
- POSTGRES_DB
- DB_HOST
- DB_PORT
- JWT_SECRET (at least 32 characters)
- MASTER_KEY (exactly 32 characters)
- MFA_ENC_KEY (exactly 32 characters)

Optional:

- ENFORCE_ENCRYPTED_METADATA (default: true)
- ENABLE_HSTS (default: false)

Example:

```env
POSTGRES_USER=securevault
POSTGRES_PASSWORD=securevault_dev_password
POSTGRES_DB=securevault
DB_HOST=db
DB_PORT=5432

JWT_SECRET=replace_with_at_least_32_characters_secret
MASTER_KEY=replace_with_exactly_32_chars_key
MFA_ENC_KEY=replace_with_exactly_32_chars_key

ENFORCE_ENCRYPTED_METADATA=true
ENABLE_HSTS=false
```

## Quick Start (Docker)

From repository root:

```bash
docker compose up --build
```

Services:

- Frontend: http://localhost:3000
- Backend: http://localhost:8080
- Postgres: localhost:5432

## Local Development (Without Docker)

### 1) Backend

```bash
cd backend
go mod download
go run .
```

### 2) Frontend

```bash
cd frontend/password_manager
npm ci
npm run dev
```

Frontend development server defaults to Vite local dev settings.

Note: The frontend API client currently targets http://localhost:8080.

## Testing

Backend tests:

```bash
cd backend
go test ./...
```

Frontend lint/build:

```bash
cd frontend/password_manager
npm run lint
npm run build
```

## API Contract and Codegen

- OpenAPI source: api-specs/openapi.yml
- Backend codegen config: backend/api.cfg.yml
- Generated bindings: backend/api/api.gen.go

When API handlers change, keep the OpenAPI spec and generated code in sync.

## Known Gaps (WIP)

- Root-level docs are still being expanded
- CI quality gates are not fully documented here yet
- Frontend folder structure should be standardized and clarified further
- Deployment docs for Kubernetes are incomplete

## Security Notes

- Do not commit real secrets or production keys
- Rotate keys and secrets outside local development
- Treat .env values as sensitive material
- This project is not yet production-hardened end-to-end

## Roadmap (Short Term)

- Improve onboarding docs and architecture diagrams
- Tighten OpenAPI-to-handler parity checks
- Add complete CI pipeline (lint, tests, build)
- Add stronger release/readiness checklist

## Contributing

Contributions and cleanup PRs are welcome while the project is in WIP status.

If you open an issue or PR, include:

- What changed
- Why it changed
- How you validated it (tests/lint/manual flow)
