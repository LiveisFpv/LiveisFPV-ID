# LiveisFPV ID (Auth/Identity API)

LiveisFPV ID is a Go-based identity and authentication service that powers registration, password authentication, OAuth 2.0 login, secure session refresh, email confirmation, and admin-controlled account management. It provides centralized login and account data across multiple apps. The API is documented with Swagger, ships with Docker Compose (core, Postgres, Redis, nginx, certbot, migrator), and exposes an internal gRPC surface alongside HTTP.

## Highlights
- JWT (HS256) access tokens plus Redis-backed refresh sessions and a token/JTI blocklist for logout and password-reset enforcement.
- Self-service registration, email confirmation, profile updates, locale support, password reset with SMTP-delivered one-time links, and admin CRUD with role management.
- OAuth 2.0 flows for Google and Yandex that use signed state JWTs, nonce cookies, and redirect whitelists; VK endpoints exist as stubs.
- Reverse-proxy friendly: nginx templates + certbot volumes for HTTPS, optional Swagger Basic Auth, strict CORS/redirect configuration, and Makefile helpers.
- Tooling includes Air for hot reload, golang-migrate wrapper, generated Swagger spec, GitHub Actions deploy workflow, and gRPC proto/generation.

## Stack & Components

| Layer | Tech | Notes |
| --- | --- | --- |
| Language/runtime | Go 1.24+ (Dockerfile uses 1.25-alpine) | Modules in `go.mod`; Air handles live reload during `docker compose up`. |
| HTTP/API | Gin, gin-contrib/cors, logrus, swaggo | Middlewares for admin auth/logging; Swagger served at `/swagger/index.html`. |
| gRPC | grpc-go + protobuf | Internal API in `api/live_id/v1` (Auth/User services). |
| Persistence | PostgreSQL 17 (users), Redis 8 (sessions & blocklist) | Redis stores `session:<id>`, `refresh_token:<token>`, `user_sessions:<userID>` and token blocklist entries. |
| Auth | golang-jwt/jwt/v5, bcrypt, custom session/jwt/email services | JWT TTLs are `CustomDuration`s from env; password reset tokens are signed JWTs with SMTP secret. |
| Tooling | `tools/migrator` (golang-migrate), `.air.toml`, Makefile, Swagger docs | `swag init` regenerates `docs/swagger.{json,yaml}`. |
| Deployment | Docker Compose (core, postgres, redis, migrator, nginx, certbot), GitHub Actions | `.github/workflows/deploy.yml` SSHes to the VPS, pulls main, rebuilds, and restarts compose stack. |

## Repository Layout

```
.
├─ cmd/                     # main entrypoint (HTTP server + Swagger wiring)
├─ internal/
│  ├─ app/                  # service wiring and dependency graph
│  ├─ config/               # cleanenv config structs
│  ├─ domain/               # entities and JWT/email claim structs
│  ├─ repository/
│  │  ├─ postgres/          # pgx user repository (CRUD, filters)
│  │  ├─ redis/             # refresh sessions + token blocklist
│  │  └─ minio/             # placeholder for object storage
│  ├─ service/              # auth, jwt, session, email, oauth orchestration
│  └─ transport/http/       # gin server, routers, handlers, middleware, presenters
├─ pkg/
│  ├─ logger/               # logrus setup + gRPC logging interceptor
│  └─ storage/              # Postgres, Redis, MinIO client helpers
├─ api/live_id/v1/         # gRPC proto + generated stubs (internal API)
├─ db/migrations/           # SQL migrations (golang-migrate compatible)
├─ tools/migrator/          # standalone migrator with CLI flags
├─ docs/                    # generated Swagger spec (keep in sync via `swag init`)
├─ nginx/, certbot/         # templated reverse proxy and Let's Encrypt volumes
├─ docker-compose.yml, dockerfile, .air.toml, Makefile
└─ .github/workflows/deploy.yml
```

## Feature Overview

### Authentication & Session Lifecycle
- Credentials live in the `users` table (see `db/migrations/1_init.up.sql`) with `roles`, `locale`, social IDs, and `email_confirmed`.
- `JWTService` issues HS256 access/refresh tokens with TTLs from env (`ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL`). Each access token carries a JTI that is stored when refresh sessions are created.
- `SessionService` persists refresh sessions in Redis (`session:<id>`, `refresh_token:<token>`) and keeps a `user_sessions:<userId>` set for bulk revocation. On logout or password resets it deletes sessions and adds the access-token JTI to the blocklist.
- `TokenBlocklist` is a thin Redis wrapper that stores revoked JTIs as expiring keys; it is also reused to mark consumed password reset tokens.
- `CookieConfig` dictates path/domain/secure/HTTP-only/SameSite/max-age for the `refresh_token` cookie so browsers enforce the correct policy.

### Account & Admin Workflows
- Registration (`POST /api/auth/create`) hashes passwords with bcrypt, stores the user as inactive, and sends an email confirmation link signed with `SMTP_JWT_SECRET`. `GET /api/auth/confirm-email` flips `email_confirmed`.
- Authenticated users can update their profile (`PUT /api/auth/update`) and optionally password/locale/photo. The handler re-validates the bearer token via `AuthService.Authenticate`.
- Password reset is a two-step flow: request (`POST /api/auth/password-reset`) issues a JWT link valid for 7 days; confirm (`GET /api/auth/password-reset/confirm`) validates the token, generates a random password, revokes all sessions, marks the token as used in Redis, and emails the new password.
- Admin endpoints under `/api/auth/admin/*` let privileged users list, create (with custom roles), and update users. The `AdminOnly` middleware treats any user with role `ADMIN` or email listed in `DEFAULT_ADMIN_EMAILS` (case-insensitive) as an administrator.

### OAuth Flows
- Google and Yandex providers share `OAuthService`. A signed JWT “state” (subject `oauth_state`) includes a nonce (stored in the `oauth_state` cookie) and an optional redirect URL. State expires after 5 minutes and is signed with `JWT_SECRET_KEY`.
- Redirect URLs must either exactly match or share scheme+host with an entry in `ALLOWED_REDIRECT_URLS`. Path prefixes are allowed so you can whitelist `https://app.example.com/auth` and serve deeper routes beneath it.
- Callback handlers upsert users: match by provider ID, fall back to email resolution, set profile fields (photo, names), mark email confirmed, and issue tokens + Redis sessions + `refresh_token` cookie. If the redirect is allowed the API responds with a 307 to the frontend, otherwise JSON is returned.
- VK endpoints and `internal/service/oauth/vkid_service.go` are present but currently return `501 Not Implemented`; compose still exposes `VK_CLIENT_ID/SECRET` for future support.

### Infrastructure & Tooling
- `.air.toml` compiles `./cmd` to `/tmp/main`; the Dockerfile installs Air and runs it so local changes trigger rebuilds inside containers.
- `tools/migrator` wraps `github.com/golang-migrate/migrate/v4`, forces out of dirty states, and can optionally roll back + reset when a migration fails.
- `docs/swagger.*` and `docs/docs.go` are generated via `swag init -g cmd/main.go -o docs`; keep comments in handlers up to date.
- `api/live_id/v1/*.proto` plus `pkg/logger/interceptor.go` back the internal gRPC server (`GRPC_PORT`/`GRPC_TIMEOUT`).
- `pkg/storage/minio.go` and `config.MinioConfig` implement a verified MinIO client (bucket existence check) that you can wire in when user uploads/avatars move to object storage.
- The nginx container renders templates based on certificate availability: HTTP-only proxy until certs exist; once certs live under `certbot/conf`, HTTPS is enabled and HTTP redirects to HTTPS.

## API Surface (summary)

Full details (request/response schemas, error payloads, query params) live in [docs/swagger.json](docs/swagger.json) and are served at `http://<DOMAIN>:<HTTP_PORT>/swagger/index.html`.

### gRPC (internal)

The gRPC surface is intentionally smaller than HTTP and is meant for internal service-to-service calls. Services live in `api/live_id/v1`:

- **AuthService**: `Authenticate`, `Validate`
- **UserService**: `CreateUser`, `UpdateUser`

Access tokens can be supplied either via the `access_token` field (for `UpdateUser`) or `authorization` metadata (`Bearer <token>` or raw token).


### Auth Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/create` | Register user, hash password, send confirmation email. |
| `GET` | `/api/auth/confirm-email?token=` | Validate email-confirmation token (24 h TTL) and mark user confirmed. |
| `POST` | `/api/auth/login` | Exchange email/password for access token (response) and refresh cookie. |
| `POST` | `/api/auth/refresh` | Rotate tokens via refresh cookie, update Redis session, issue new cookie. |
| `POST` | `/api/auth/logout` | Delete refresh session, blocklist JTI, clear cookie. |
| `GET` | `/api/auth/authenticate` | Return user profile inferred from bearer access token. |
| `GET` | `/api/auth/validate` | Validate bearer access token; returns 200/401 only. |
| `PUT` | `/api/auth/update` | Update profile/password/locale; requires bearer token. |
| `POST` | `/api/auth/password-reset` | Send password-reset email (no-op if user missing). |
| `GET` | `/api/auth/password-reset/confirm?token=` | Redeem reset token, generate new password, revoke sessions, email the temp password. |

### OAuth Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/oauth/google?redirect_url=` | Start Google OAuth, issue signed state + nonce cookie. |
| `GET` | `/api/oauth/google/callback` | Complete Google OAuth, mint tokens/session, redirect or return JSON. |
| `GET` | `/api/oauth/yandex?redirect_url=` | Start Yandex OAuth, same mechanics as Google. |
| `GET` | `/api/oauth/yandex/callback` | Complete Yandex OAuth. |
| `GET` | `/api/oauth/vk` | Placeholder; returns 501. |
| `GET` | `/api/oauth/vk/callback` | Placeholder; returns 501. |

### Admin Endpoints (require `ADMIN` role or `DEFAULT_ADMIN_EMAILS`)

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/auth/admin/users` | Paginated, filterable list (`q`, `role`, `email_confirmed`, `locale`, `page`, `limit`). |
| `POST` | `/api/auth/admin/users` | Create user with explicit roles. |
| `PUT` | `/api/auth/admin/users/:id` | Update user data/profile/roles without needing their access token. |

## Getting Started

### Requirements
- Go 1.24+ (for native runs), Docker + Docker Compose v2 (for stack), and `swag` CLI if you modify handler docs.
- Running PostgreSQL and Redis instances (Compose provides both).

### Docker Compose (all-in-one stack)
1. Create the shared external network once (Compose expects it): `docker network create grpc_network`.
2. Copy `.env` (see Configuration section) and set at minimum: `DOMAIN`, `HTTP_PORT`, `JWT_SECRET_KEY`, `ALLOWED_CORS_ORIGINS`, `ALLOWED_REDIRECT_URLS`, database/Redis credentials, SMTP settings, and optionally `DEFAULT_ADMIN_EMAILS` for bootstrap admins.
3. Start everything: `docker compose up --build` (or `make deploy`). Services include `core`, `postgres`, `redis`, `migrator`, `nginx`, and `certbot`.
4. Visit Swagger UI at `http://localhost:8080/swagger/index.html` (or via nginx if TLS is configured).
5. To rebuild without cache: `make rebuild`. To stop: `make down`. Logs: `make logs`.

### Local Development without Docker
1. Ensure Postgres & Redis are running and accessible via the env vars you intend to use. You can run them via Docker (`docker compose up postgres redis`) or locally.
2. Export env vars (`cp .env .env.local && source .env.local` on Unix shells) or rely on OS-level env values.
3. Run the API: `go run ./cmd`. For live reload outside containers install Air (`go install github.com/air-verse/air@latest`) and run `air -c .air.toml`.

### Database Migrations
- SQL lives under `db/migrations`. Compose starts the `migrator` service after Postgres healthchecks, which runs all pending migrations and exits.
- To run migrations manually: `make migrate` or `docker compose run --rm migrator`.
- Standalone execution example:
  ```sh
  go run ./tools/migrator \
    -user="$DB_USER" -password="$DB_PASSWORD" \
    -host="$DB_HOST" -port="$DB_PORT" -dbname="$DB_NAME" \
    -migrations-path="$(pwd)/db/migrations"
  ```

### Swagger Docs Regeneration
1. Install the CLI once: `go install github.com/swaggo/swag/cmd/swag@latest`.
2. From repo root run `make swag` (alias for `swag init -g cmd/main.go -o docs`).

### Makefile Shortcuts

| Command | Description |
| --- | --- |
| `make deploy` / `make up` | Build + start stack (detached). |
| `make down` | Stop stack. |
| `make logs` | Tail container logs. |
| `make rebuild` | Rebuild without cache, then start. |
| `make restart` | Restart only the `core` service. |
| `make network` | Create the external `grpc_network` if missing. |
| `make migrate` | Run migrator ad-hoc. |
| `make swag` | Regenerate Swagger docs. |
| `make clean` | `docker system prune` and delete dangling volumes (use cautiously). |

### GitHub Actions Deployment
`.github/workflows/deploy.yml` SSHes into your VPS using secrets (`SSH_HOST`, `SSH_USER`, `SSH_PRIVATE_KEY`), pulls `main`, rebuilds the compose images, and restarts the stack. This keeps all deployment logic on the server (no docker context upload) and relies on the repo already being cloned on the VPS at `~/LiveisFPV-ID`.

## Configuration Reference

> The project uses `cleanenv`. If an environment variable exists but is empty (e.g., `DOMAIN=`), the default is **not** applied; delete unset variables instead of setting them to an empty string.

### Core HTTP, Admin, Docs
- `DOMAIN` (default `localhost`): base host for cookies and logging (no scheme). Use `.example.com` to share cookies across subdomains.
- `PUBLIC_URL`: fully qualified URL (scheme + host [+ port]) used in OAuth callbacks and email links. Falls back to `http://DOMAIN:HTTP_PORT` if empty.
- `HTTP_PORT` (default `8080`): Gin listener and internal service port (`nginx` proxies to it).
- `ALLOWED_CORS_ORIGINS` (comma list, **required**): frontends permitted by CORS; the server fails to start when empty.
- `ALLOWED_REDIRECT_URLS` (comma list): whitelisted redirect targets for OAuth `redirect_url`.
- `DEFAULT_ADMIN_EMAILS` (comma list): bootstrap admin emails recognized by `AdminOnly` middleware even if `roles` array lacks `ADMIN`.
- `SWAGGER_ENABLED` (default `true`): disable to completely remove `/swagger`.  
  `SWAGGER_USER`/`SWAGGER_PASSWORD`: if both set, Swagger endpoints are protected with Basic Auth.

### Database & Redis
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSL` (default `disable`).
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB` (default `0`). Redis is required; sessions and blocklist depend on it.

### JWT & Cookies
- `JWT_SECRET_KEY`: signing key for access/refresh tokens **and** OAuth state tokens.
- `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL`: support suffixes `s`, `m`, `h`, `d`, `mo` (30-day months).
- `COOKIE_PATH` (default `/`), `COOKIE_SECURE` (default `false`), `COOKIE_HTTP_ONLY` (default `true`), `COOKIE_MAX_AGE` (default `7d`), `COOKIE_SAME_SITE` (`Lax`, `Strict`, or `None`). Domain is inherited from `DOMAIN`.

### Email / SMTP
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `FROM_EMAIL`.
- `SMTP_JWT_SECRET`: separate signing key for email confirmation + password reset JWTs.

### OAuth Providers
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`.
- `YANDEX_CLIENT_ID`, `YANDEX_CLIENT_SECRET`.
- `VK_CLIENT_ID`, `VK_CLIENT_SECRET` (currently unused placeholders).

### Misc / Optional
- `GRPC_PORT` (default `50051`), `GRPC_TIMEOUT` (default `24h`): gRPC listener config (internal API).
- MinIO (currently unused but validated): `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`, `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_USE_SSL`, `MINIO_BUCKET_NAME`.

## Operations & Deployment Notes

### Session & Cookie Behavior
- Refresh tokens live only in the `refresh_token` cookie, so frontend apps must send requests with `credentials: 'include'`.
- For cross-site setups (frontend domain != API domain) `COOKIE_SAME_SITE=None` **and** `COOKIE_SECURE=true` are required; serve the API over HTTPS via nginx.
- Logout marks the access-token JTI as blocked until its original expiry. Password reset confirmation additionally blocklists the password-reset token ID for the remainder of its TTL to prevent reuse.
- Redis stores per-user sets, so `SessionService.DeleteAllUserSessions` can revoke all outstanding refresh sessions when needed (e.g., password reset).

### Email & Password Reset
- Email confirmation tokens expire after 24 h; password-reset tokens after 7 days. Both are signed using `SMTP_JWT_SECRET` and embed user ID + email + (for resets) JWT ID.
- Password reset confirmation generates a random 12–16 character password (no reuse of the submitted token), updates the hash in Postgres, revokes every session, optionally warns if stored email differs from token email, and emails the new password via SMTP.

### OAuth Redirect Safety
- Always include only fully-qualified URLs in `ALLOWED_REDIRECT_URLS`. The backend checks scheme + host equality and ensures the callback path either exactly matches or is beneath the allowed path.
- The `oauth_state` cookie TTL is 5 minutes; expired or mismatched state/nonce pairs are rejected to prevent CSRF.

### Reverse Proxy & TLS
1. Point DNS for `DOMAIN` to your VPS.
2. Set `DOMAIN`, `PUBLIC_URL=https://<domain>`, and update `ALLOWED_CORS_ORIGINS` / `ALLOWED_REDIRECT_URLS` with HTTPS origins.
3. Start core + nginx: `docker compose up -d core nginx`.
4. Issue certificates via webroot challenge (runs once per domain):
   ```sh
   DOMAIN=id.example.com docker compose run --rm certbot \
     certonly --webroot -w /var/www/certbot \
     -d "$DOMAIN" --email you@example.com --agree-tos -n
   ```
5. Restart nginx: `docker compose restart nginx`.
6. Automate renewal (cron on VPS, e.g. daily at 3 AM):
   ```
   0 3 * * * cd /path/to/authorization_service && \
     docker compose run --rm certbot renew --webroot -w /var/www/certbot && \
     docker compose exec -T nginx nginx -s reload
   ```
The nginx entrypoint auto-detects certificates; before certs exist it serves HTTP only, afterwards it enforces HTTPS and keeps port 80 for ACME challenges.

### Deployment Automation
- Configure `SSH_HOST`, `SSH_USER`, `SSH_PRIVATE_KEY` secrets in GitHub. The `deploy.yml` workflow triggers on pushes to `main` and performs `git pull`, `docker compose build`, `docker compose down`, and `docker compose up -d` on the remote VPS repo clone.

### Logging & Monitoring
- Logrus outputs JSON with RFC3339 timestamps by default (`pkg/logger/setup.go`). Optional request/response middlewares live under `internal/transport/http/middlewares/logging.go` (disabled by default—enable if you need detailed request logs).
- `pkg/logger/interceptor.go` defines a gRPC logging interceptor used by the internal gRPC server.

### Troubleshooting Tips
- **“no allowed CORS origins configured” on startup:** ensure `ALLOWED_CORS_ORIGINS` is non-empty.
- **Cookies missing in browser:** confirm the frontend origin matches an entry in `ALLOWED_CORS_ORIGINS`, `SameSite`/`Secure` flags match your deployment, and requests include credentials.
- **OAuth callback returns JSON instead of redirect:** provide `redirect_url` and add it (or its origin/path) to `ALLOWED_REDIRECT_URLS`.
- **Swagger 401/404:** if you enabled Basic Auth, append credentials via browser prompt; set `SWAGGER_ENABLED=true` to expose the UI.

## Tooling & Future Work
- gRPC is already wired for internal auth/user flows; expand only if another internal consumer requires additional methods.
- `internal/repository/minio` and `pkg/storage/minio` are ready once object storage is required (bucket existence is validated before use).
- VK OAuth placeholders share the same pattern as Google/Yandex; complete `internal/service/oauth/vkid_service.go` and wire credentials to support it.
- Automated tests are currently absent; plan to add unit tests around services (JWT/email/session) and repository integration tests to guard future changes.

## License

Licensed under the [Apache License 2.0](LICENSE).
