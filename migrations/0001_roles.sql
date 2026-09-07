-- Postgres roles. Created idempotently so `sqlx migrate run` is safe to re-run
-- against a cluster where the roles already exist (roles are cluster-scoped,
-- not database-scoped, so a fresh database on an existing cluster still finds
-- them).
--
-- Three roles, three jobs:
--   migrator        - owns the tables; what migrations connect as.
--   invoice_app     - what the API connects as for request handling. No table
--                     ownership, no BYPASSRLS: every query it runs is filtered
--                     by the RLS policies in sql/rls.sql.
--   invoice_service - background workers (webhook dispatcher, payment
--                     reconciler). These are legitimately cross-tenant, so
--                     they get their own policies granting exactly that, on
--                     exactly the tables they need.
--
-- DEV-ONLY PASSWORDS. These are baked in so `docker compose up` is zero-step.
-- In production these roles would be provisioned out of band with secrets from
-- a secret manager; see DESIGN.md "Production gaps".

DO $$ BEGIN
    CREATE ROLE invoice_app LOGIN PASSWORD 'invoice_app_dev_password';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE ROLE invoice_service LOGIN PASSWORD 'invoice_service_dev_password';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- The API process runs both request handlers and background workers. Rather
-- than a second connection pool, background work does `SET LOCAL ROLE
-- invoice_service` inside its transaction. INHERIT FALSE means invoice_app
-- does *not* ambiently carry invoice_service's cross-tenant grants - it has to
-- ask for them explicitly, per transaction, and the switch dies at COMMIT.
GRANT invoice_service TO invoice_app WITH INHERIT FALSE;
