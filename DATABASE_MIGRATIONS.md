# Database migrations

Flyway owns the PostgreSQL schema. Migrations live in `src/main/resources/db/migration` and run automatically when the service starts. Hibernate is set to `validate`, so it checks the migrated schema without changing it.

`V1__create_auth_tables.sql` creates the initial user and refresh-token tables. `V2__add_device_sessions.sql` adds the per-device session fields. `V3__remove_revoked_and_expired_refresh_tokens.sql` removes obsolete refresh-token records. The baseline settings let an existing non-empty database created by the previous Hibernate setup be adopted at version 1; Flyway then applies V2 and V3 without dropping active records. A fresh database runs all migrations normally.

For future schema changes, add a new, higher-numbered migration such as `V4__add_user_status.sql`. Do not edit migrations that have already run in a shared environment; add another migration instead.
