# Auth Service

Spring Boot authentication service for a microservice project. It uses PostgreSQL, signed JWT access tokens, and rotating refresh tokens stored in an HttpOnly cookie. Each login creates an independent device session; the server derives a display label from the request's `User-Agent` header.

## Configuration and run

The service gets its main configuration from Spring Cloud Config using the application name `auth-service`. Keep an `auth-service.yml` in the Config Server Git repository. Provide its URL as `CONFIG_SERVER_URI` and provide the database and JWT values required by that remote configuration through the service environment.

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
| `GET` | `/hello` | Example protected endpoint |

Register and login accept JSON with `email` and `password`. The refresh token is set as an HttpOnly cookie; refresh requests need no JSON body. Send the access token to protected routes as `Authorization: Bearer <access-token>`. Postman can store the login response's `accessToken` in an environment variable and automatically retain the refresh cookie for the same host.

For curl, use a cookie jar so repeat logins from the same terminal can present the existing refresh token: `curl -c cookies.txt -b cookies.txt ...`. Without `-b`, curl does not send the saved cookie, so each successful login starts a new session.

## Database migrations

Flyway runs migrations from `src/main/resources/db/migration` at startup. Hibernate validates the schema and does not update it. See [DATABASE_MIGRATIONS.md](DATABASE_MIGRATIONS.md) for the existing-database baseline behavior and migration naming guidance.
