# Auth Service

Spring Boot authentication service for a microservice project. It uses PostgreSQL, signed JWT access tokens, and rotating refresh tokens stored in an HttpOnly cookie. Each login creates an independent device session; the server derives a display label from the request's `User-Agent` header.

## Configuration and run

The service gets its main configuration from Spring Cloud Config using the application name `auth-service`. Keep an `auth-service.yml` in the Config Server Git repository. Provide its URL as `CONFIG_SERVER_URI` and provide the database and JWT values required by that remote configuration through the service environment.

Add Google OAuth client settings to that remote `auth-service.yml` (or local configuration):

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: [openid, profile, email]
```

Create a Google OAuth 2.0 Web application client and register `http://localhost:8080/login/oauth2/code/google` as an authorized redirect URI. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in the auth-service process environment (or config server environment). The Google login entry point is `GET /oauth2/authorization/google`; after consent Google redirects to the callback and the service responds with its normal access-token JSON plus the HttpOnly `refreshToken` cookie. A verified Google email creates a passwordless local account on first sign-in; later sign-ins use the same account. Existing password accounts with the same normalized email are linked to that Google identity.

Copy `.env.example` to `.env` and replace the placeholders. Spring Boot does not load `.env` automatically. In a Bash shell, load it before starting the app:

```bash
set -a
source .env
set +a
./mvnw spring-boot:run
```

In IntelliJ, add the variables to the run configuration's environment variables. Use Java 21 or newer. Generate a JWT secret with `openssl rand -base64 32`. Set `AUTH_COOKIE_SECURE=true` when serving over HTTPS.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/auth/register` | Create an account; returns user details and an access token |
| `POST` | `/auth/login` | Log in; returns an access token |
| `POST` | `/auth/refresh` | Rotate the refresh cookie and return a new access token |
| `POST` | `/auth/logout` | Revoke the current device session and clear its cookie |
| `GET` | `/oauth2/authorization/google` | Start Google sign-in or sign-up |
| `GET` | `/hello` | Example protected endpoint |

Register and login accept JSON with `email` and `password`. The refresh token is set as an HttpOnly cookie; refresh requests need no JSON body. Send the access token to protected routes as `Authorization: Bearer <access-token>`. Postman can store the login response's `accessToken` in an environment variable and automatically retain the refresh cookie for the same host.

`POST /auth/refresh` rotates the refresh token on every successful use. The previous token is retained as a revoked token record (only its SHA-256 hash is stored) until it expires. Reuse of a rotated token revokes all refresh tokens for that device session and returns `401`; the user must sign in again. Keep the refresh cookie enabled so the client receives the replacement token on each successful refresh.

For curl, use a cookie jar so repeat logins from the same terminal can present the existing refresh token: `curl -c cookies.txt -b cookies.txt ...`. Without `-b`, curl does not send the saved cookie, so each successful login starts a new session.

### Test Google sign-in with Postman (no frontend)

1. Set up the Google OAuth client above and start the service. Ensure the callback URL exactly matches `http://localhost:8080/login/oauth2/code/google`.
2. In Postman, create a request with method `GET` and URL `http://localhost:8080/oauth2/authorization/google`. Send it with automatic redirect following enabled. Postman opens the Google sign-in/consent redirect chain and completes the callback; sign in with a Google account added as a test user if the OAuth consent screen is in testing mode.
3. The final callback response is JSON containing `accessToken`, `tokenType`, `expiresIn`, `userId`, `email`, and `sessionId`. Postman stores the `refreshToken` cookie for `localhost` automatically.
4. Copy `accessToken` into `Authorization: Bearer <access-token>` on a protected request such as `GET http://localhost:8080/hello`. Use `POST /auth/refresh` to rotate the stored cookie and obtain a fresh access token; `POST /auth/logout` revokes that session.

If Postman cannot complete Google consent in its redirect window, open the same authorization URL in a browser; the callback still returns the token JSON there. For a Postman-only flow, use Postman's OAuth 2.0 authorization helper with Google authorization/token endpoints and the same client, then note that this service's browser callback flow is the one that creates/links the local user and issues its own app tokens.

## Database migrations

Flyway runs migrations from `src/main/resources/db/migration` at startup. Hibernate validates the schema and does not update it. See [DATABASE_MIGRATIONS.md](DATABASE_MIGRATIONS.md) for the existing-database baseline behavior and migration naming guidance.
