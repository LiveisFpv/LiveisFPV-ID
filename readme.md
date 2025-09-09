# LiveisFPV ID (SSO API)

Single Sign-On and authentication service written in Go. Provides user registration and login, JWT access/refresh tokens, Redis-backed sessions and token blocklist, email confirmation, and OAuth 2.0 login via Google. HTTP API is documented with Swagger; core settings (domain/ports/CORS/redirects) are configured via environment variables.

- Language: Go 1.24
- HTTP: Gin
- Auth: JWT (HS256), refresh sessions in Redis, token blocklist by JTI
- OAuth: Google (OIDC userinfo) and Yandex, multi-frontend redirects
- Storage: PostgreSQL (users), Redis (sessions, blocklist)
- Docs: Swagger UI at `/swagger/index.html`

## Quick Start (Docker)

Prereqs:
- Docker + Docker Compose
- Optional: Go 1.24 (for local dev)

Steps:
1) Create external network once (compose expects it):
   - `docker network create grpc_network`
2) Copy `.env` and fill required variables (see below). Minimal local setup:
   - `DOMAIN=localhost`
   - `JWT_SECRET_KEY=change_me`
   - `ALLOWED_CORS_ORIGINS=http://localhost:5173,http://localhost:8080`
   - `ALLOWED_REDIRECT_URLS=http://localhost:5173`
   - Google/Yandex OAuth credentials if using OAuth
3) Start services:
   - `docker compose up --build`
4) Open Swagger UI:
   - `http://localhost:8080/swagger/index.html`

Compose services:
- `core`: the API server
- `postgres`: main DB
- `redis`: sessions/blocklist
- `migrator`: runs DB migrations from `db/migrations`

## Configuration (.env)

The service uses cleanenv to load settings. Important variables:

- `DOMAIN`: Public hostname used for URLs/cookies (e.g. `localhost`, `.example.com`).
- `ALLOWED_CORS_ORIGINS`: Comma-separated list of origins allowed by CORS (e.g. `http://localhost:5173`). Required; the server fails to start if empty.
- `ALLOWED_REDIRECT_URLS`: Comma-separated list of allowed redirect URLs for OAuth (e.g. `http://localhost:5173`).
- `PUBLIC_URL`: Externally reachable URL of this service (e.g. `https://id.example.com`). Used to build OAuth callbacks and emails.

PostgreSQL:
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `DB_SSL` (default `disable`)

Redis:
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`
- `REDIS_DB` (default `0`)

Email (for confirmations):
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `FROM_EMAIL`
- `SMTP_JWT_SECRET`: Secret used to sign email confirmation tokens

JWT:
- `JWT_SECRET_KEY`: Secret key used to sign tokens
- `ACCESS_TOKEN_TTL`: Access token lifetime (supports `s`, `m`, `h`, `d`, `mo`) - e.g. `15m`
- `REFRESH_TOKEN_TTL`: Refresh token lifetime - e.g. `7d`

Cookies:
- `COOKIE_PATH` (default `/`)
- `COOKIE_SECURE` (`true` in production)
- `COOKIE_HTTP_ONLY` (default `true`)
- `COOKIE_MAX_AGE` (duration like `7d`)
- Note: Cookie domain is taken from `DOMAIN`.
- `COOKIE_SAME_SITE` (default `Lax`): one of `Lax`, `Strict`, `None`. For cross‑site flows (frontend on another origin), set `None` and ensure `COOKIE_SECURE=true`.

gRPC (scaffolding present, not started by default):
- `GRPC_PORT` (default `50051`)
- `GRPC_TIMEOUT` (default `24h`)

HTTP:
- `HTTP_PORT` (default `8080`)

OAuth (Google/Yandex):
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `YANDEX_CLIENT_ID`, `YANDEX_CLIENT_SECRET`

Tip: If you set an env var to an empty string (e.g. `DOMAIN=`) the library treats it as set, so env-default will not apply. Set a real value or remove the variable.

## Endpoints (HTTP)

Base path: `/api`

Auth:
- `POST /api/auth/create` - Register user; sends email confirmation.
- `GET  /api/auth/confirm-email?token=...` - Confirm email.
- `POST /api/auth/login` - Login; returns tokens and sets refresh cookie.
- `POST /api/auth/refresh` - Issue new tokens by refresh cookie; sets new cookie.
- `POST /api/auth/logout` - Logout; deletes session and clears cookie.
- `GET  /api/auth/authenticate` - Return current user by access token.
- `GET  /api/auth/validate` - Validate access token only.

OAuth:
- `GET /api/oauth/google?redirect_url=<frontend>` - Start Google OAuth. Saves state cookie (and redirect_url if allowed) and redirects to Google.
- `GET /api/oauth/google/callback?code=...&state=...` - Callback. Creates session, sets refresh cookie and either:
  - Redirects (307) to allowed `redirect_url` (if provided/allowed), or
  - Returns JSON with `{ "error": "..." }`.
- `GET /api/oauth/yandex?redirect_url=<frontend>` - Start Yandex OAuth. Saves state cookie (and redirect_url if allowed) and redirects to Yandex.
- `GET /api/oauth/yandex/callback?code=...&state=...` - Callback. Creates session, sets refresh cookie and either:
  - Redirects (307) to allowed `redirect_url` (if provided/allowed), or
  - Returns JSON with `{ "error": "..." }`.

VK routes exist but currently return "Not Implemented".

## OAuth Notes

- Signed state (JWT) with nonce and optional redirect_url is used for Google and Yandex. State is validated in callback; nonce is stored in `oauth_state` cookie.
- Google: OIDC userinfo; primary id is `sub` (fallback to `id`). Scopes include `openid`, `userinfo.profile`, `userinfo.email`.
- Yandex: userinfo from https://login.yandex.ru/info?format=json with `login:email` and `login:info` scopes.
- Multi-frontend flow:
  - Frontend calls `/api/oauth/{provider}?redirect_url=<encoded URL>`.
  - Backend validates redirect_url against `ALLOWED_REDIRECT_URLS`, embeds it into the signed state and redirects to provider.
  - After callback, backend sets the refresh cookie and redirects (307) to that redirect_url or returns JSON with access token.
  - Frontend calls `/api/auth/refresh` with `credentials: 'include'` to obtain an access_token.

## Swagger

- Swagger UI: `GET /swagger/index.html`
- Host and basePath are set dynamically from `DOMAIN` and `HTTP_PORT` at server startup.
- To regenerate docs after handler comment changes:
  1) `go install github.com/swaggo/swag/cmd/swag@latest`
  2) From repo root: `swag init -g cmd/main.go -o docs`

## Data & Migrations

- Migrations live in `db/migrations`. A small migrator in `tools/migrator` runs at startup in Compose.
- Users table (`db/migrations/1_init.up.sql`) includes fields for OAuth IDs and has defaults (`roles` default to `{"USER"}`, `locale` default `ru`).
- Repository uses pgx; user lookups by id/email/google_id.

## Internals (Overview)

- `internal/app`: wires config, repositories, and services.
- `internal/config`: `cleanenv` config structs + custom duration type.
- `internal/domain`: entities (`User`, token claims, `Session`).
- `internal/repository`: Postgres (users) and Redis (sessions, blocklist).
- `internal/service`:
  - `auth_service`: login/register/confirm/refresh/logout.
  - `jwt_service`: token creation/verification and JTI parsing.
  - `session_service`: Redis sessions; blocklist on logout.
  - `oauth/`: provider-specific clients (Google).
  - `oauth_service.go`: service-level orchestration for OAuth login/callback.
- `internal/transport/http`: Gin server, CORS, routers, handlers, presenters.
- `internal/transport/rpc`: gRPC scaffolding (not wired in `main.go`).

## Local Development

Run without Docker (requires running Postgres + Redis):
- Set `.env` and export variables, or rely on OS env.
- `go run ./cmd`

Formatting/Build:
- `go build ./...`

Swagger dev:
- Update handler annotations and run `swag init` (see Swagger section).

## VPS Deployment (Makefile)

Run these commands directly on the VPS in the repo directory:
- `make deploy` - build and start (detached)
- `make logs` - tail logs
- `make down` - stop stack
- `make rebuild` - rebuild without cache and start
- `make restart` - restart only `core` service
- `make migrate` - run migrator one-off (optional)
- If you use Compose v2 plugin, run with `DC="docker compose"`, e.g.: `make deploy DC="docker compose"`

## Reverse Proxy (nginx) + HTTPS (Let's Encrypt)

Compose already contains `nginx` and `certbot` services to terminate TLS and proxy to `core`:

1) DNS: point `DOMAIN` (e.g. `id.example.com`) A/AAAA records to your VPS IP.
2) Set in `.env`:
   - `DOMAIN=id.example.com`
   - `PUBLIC_URL=https://id.example.com`
   - Add your frontends to `ALLOWED_CORS_ORIGINS` and `ALLOWED_REDIRECT_URLS` with https scheme.
3) Start nginx and core:
   - `docker compose up -d nginx core` (or `make deploy` to start all)
4) Issue certificate (webroot challenge):
   - `docker compose run --rm certbot certonly --webroot -w /var/www/certbot -d $env:DOMAIN --email you@example.com --agree-tos -n` (PowerShell)
   - Linux shell: `DOMAIN=id.example.com docker compose run --rm certbot certonly --webroot -w /var/www/certbot -d $DOMAIN --email you@example.com --agree-tos -n`
5) Reload nginx to enable HTTPS:
   - `docker compose restart nginx` or `docker compose exec nginx nginx -s reload`
6) Auto‑renew (cron):
   - Add a cron job on VPS: `0 3 * * * cd /opt/authorization_service && docker compose run --rm certbot renew --webroot -w /var/www/certbot && docker compose exec -T nginx nginx -s reload`

Notes
- nginx config is templated from `nginx/templates` using env `NGINX_HOST` and `CORE_UPSTREAM`. Until the cert exists, nginx serves HTTP only and redirects to HTTPS once cert is present.
- You can restrict external access to `core` by removing `HTTP_PORT` from `core` ports section if nginx is the only entrypoint.
- Ensure VPS firewall allows 80 and 443.

## Security & Deployment Notes

- Set a strong `JWT_SECRET_KEY` and rotate secrets safely.
- Use `COOKIE_SECURE=true` and HTTPS in production; consider `SameSite=None` for true cross-site flows.
- Set `DOMAIN` to a registrable/public domain (or a parent like `.example.com` for subdomains) so cookies are scoped correctly.
- Configure `ALLOWED_CORS_ORIGINS` and `ALLOWED_REDIRECT_URLS` to the exact frontends you use.
- Set `PUBLIC_URL` to an https URL in production so OAuth callbacks and email links are correct.
- Cross‑site setup (backend on domain, frontend on localhost/other domain): set `COOKIE_SAME_SITE=None`, `COOKIE_SECURE=true`, call backend over HTTPS with `credentials: 'include'`.

## Troubleshooting

- "Server is running on :8080": `DOMAIN` is empty. When env var is present but empty, default doesn't apply; set `DOMAIN=localhost` (or remove var) so default works.
- "no allowed CORS origins configured": set `ALLOWED_CORS_ORIGINS` in `.env` (comma-separated) and restart.
- OAuth callback shows backend page instead of redirect: pass `redirect_url` and allow it in `ALLOWED_REDIRECT_URLS`.
- CORS or cookies not working: ensure origin is in `ALLOWED_CORS_ORIGINS` and frontend requests use `credentials: 'include'`. For cross-site cookies you may need `Secure` and `SameSite=None`.
- Email not sent: verify SMTP settings and network egress.

## License

Repository is licensed under the Apache 2.0 license. The terms of the license are detailed in LICENSE.

