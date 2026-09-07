-- Core schema.
--
-- Conventions:
--   * every table has a UUIDv7 primary key, generated application-side
--     (Postgres 16 has no uuidv7()); sortable by creation time.
--   * every tenant-owned table carries business_id directly - it is the RLS
--     anchor, so it is denormalised onto child tables (line items, attempts)
--     rather than reached through a join.
--   * money is BIGINT cents everywhere. No floats in the money path.

CREATE TABLE businesses (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- API keys. `key_hash` is SHA-256 of the full presented key string.
--
-- Deliberately not argon2/bcrypt: those exist to make *low-entropy* secrets
-- (human passwords) expensive to brute force. These keys are 24 characters
-- drawn from OS randomness, so there is nothing to brute force; a slow KDF
-- would only add latency to every single authenticated request. Constant-time
-- comparison of a fast hash is the correct trade here. See DESIGN.md.
CREATE TABLE api_keys (
    id            UUID PRIMARY KEY,
    business_id   UUID NOT NULL REFERENCES businesses (id) ON DELETE CASCADE,
    name          TEXT NOT NULL DEFAULT '',
    key_prefix    TEXT NOT NULL,
    key_hash      TEXT NOT NULL,
    -- Scope strings: 'resource:action', with '*' allowed on either side.
    -- Validated against the grammar in auth/permissions.rs at creation time.
    permissions   TEXT[] NOT NULL,
    revoked_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX api_keys_key_prefix_idx ON api_keys (key_prefix);
CREATE INDEX api_keys_business_idx ON api_keys (business_id, created_at DESC);

CREATE TABLE customers (
    id           UUID PRIMARY KEY,
    business_id  UUID NOT NULL REFERENCES businesses (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    email        TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX customers_business_created_idx ON customers (business_id, created_at DESC, id DESC);

CREATE TABLE invoices (
    id           UUID PRIMARY KEY,
    business_id  UUID NOT NULL REFERENCES businesses (id) ON DELETE CASCADE,
    customer_id  UUID NOT NULL REFERENCES customers (id) ON DELETE RESTRICT,
    state        TEXT NOT NULL
                 CHECK (state IN ('draft', 'sent', 'partially_paid', 'paid', 'void', 'refunded')),
    -- Server-computed from the line items. Client-supplied totals are ignored.
    total_cents        BIGINT NOT NULL CHECK (total_cents >= 0),
    amount_paid_cents  BIGINT NOT NULL DEFAULT 0,
    currency     TEXT NOT NULL DEFAULT 'usd',
    due_date     DATE NOT NULL,
    sent_at      TIMESTAMPTZ,
    paid_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Structural guard on the money field: you can never have paid more than
    -- the invoice is worth, and never a negative amount.
    CONSTRAINT invoices_amount_paid_range
        CHECK (amount_paid_cents >= 0 AND amount_paid_cents <= total_cents),
    -- 'paid' means fully paid, always. This makes the state column and the
    -- money column unable to disagree.
    CONSTRAINT invoices_paid_is_settled
        CHECK (state <> 'paid' OR amount_paid_cents = total_cents),
    -- Void is only reachable when no money has moved (see the state machine).
    CONSTRAINT invoices_void_is_clean
        CHECK (state <> 'void' OR amount_paid_cents = 0)
);

CREATE INDEX invoices_business_state_idx ON invoices (business_id, state);
CREATE INDEX invoices_business_customer_idx ON invoices (business_id, customer_id);
CREATE INDEX invoices_business_created_idx ON invoices (business_id, created_at DESC, id DESC);
-- Partial index for the overdue scan: only invoices where money is still
-- collectible can be overdue, so the index only carries those rows.
CREATE INDEX invoices_overdue_idx ON invoices (business_id, due_date)
    WHERE state IN ('sent', 'partially_paid');

-- Line items are immutable once the invoice exists: an invoice's total is a
-- fact about a document that was sent to someone. Corrections are a new
-- invoice, not an edit.
CREATE TABLE invoice_line_items (
    id                 UUID PRIMARY KEY,
    invoice_id         UUID NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    business_id        UUID NOT NULL REFERENCES businesses (id) ON DELETE CASCADE,
    description        TEXT NOT NULL,
    quantity           INTEGER NOT NULL CHECK (quantity > 0),
    unit_amount_cents  BIGINT NOT NULL CHECK (unit_amount_cents >= 0),
    amount_cents       BIGINT NOT NULL CHECK (amount_cents >= 0),
    position           INTEGER NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX invoice_line_items_invoice_idx ON invoice_line_items (invoice_id, position);

CREATE TABLE payment_attempts (
    id            UUID PRIMARY KEY,
    invoice_id    UUID NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    business_id   UUID NOT NULL REFERENCES businesses (id) ON DELETE CASCADE,
    status        TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed')),
    -- Which PSP adapter handled this attempt. The reconciler needs it: a
    -- retry has to go back to the *same* provider with the same reference,
    -- or provider-side idempotency does not protect us.
    processor     TEXT NOT NULL,
    card_token    TEXT NOT NULL,
    amount_cents  BIGINT NOT NULL CHECK (amount_cents > 0),
    psp_ref       TEXT,
    failure_code  TEXT,
    -- How many times the reconciler has re-submitted this attempt after an
    -- unknown outcome. Bounded, so a permanently unreachable PSP eventually
    -- stops being retried and starts being alerted on.
    reconcile_attempts INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- THE concurrency backbone. At most one in-flight attempt per invoice, enforced
-- by the database rather than by application sequencing. Two concurrent /pay
-- requests race here and exactly one wins; the loser gets a unique violation
-- that the handler turns into 409 payment_in_progress.
--
-- Why a partial unique index rather than an advisory lock or SERIALIZABLE:
-- the guarantee has to survive the window where we hold no transaction at all
-- (the PSP call). An index does; a lock does not. See DESIGN.md §3.
CREATE UNIQUE INDEX payment_attempts_one_pending_per_invoice
    ON payment_attempts (invoice_id) WHERE status = 'pending';

CREATE INDEX payment_attempts_invoice_idx ON payment_attempts (invoice_id, created_at DESC);
-- Drives the reconciler sweep.
CREATE INDEX payment_attempts_pending_sweep_idx ON payment_attempts (updated_at)
    WHERE status = 'pending';

CREATE TABLE idempotency_keys (
    id               UUID PRIMARY KEY,
    business_id      UUID NOT NULL REFERENCES businesses (id) ON DELETE CASCADE,
    key              TEXT NOT NULL,
    -- SHA-256 over method + path + body. Same key, different request => the
    -- caller has a bug, and replaying the old response would hide it. 422.
    request_hash     TEXT NOT NULL,
    response_status  INTEGER,
    response_body    JSONB,
    locked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT idempotency_keys_business_key UNIQUE (business_id, key)
);

CREATE TABLE webhook_endpoints (
    id           UUID PRIMARY KEY,
    business_id  UUID NOT NULL REFERENCES businesses (id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    -- Returned to the caller exactly once, at creation.
    secret       TEXT NOT NULL,
    disabled_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX webhook_endpoints_business_idx ON webhook_endpoints (business_id, created_at DESC);

-- Transactional outbox. Rows are inserted in the *same transaction* as the
-- state change that caused them, so "the invoice is paid" and "someone will be
-- told the invoice is paid" commit together or not at all.
CREATE TABLE webhook_deliveries (
    id              UUID PRIMARY KEY,
    endpoint_id     UUID NOT NULL REFERENCES webhook_endpoints (id) ON DELETE CASCADE,
    business_id     UUID NOT NULL REFERENCES businesses (id) ON DELETE CASCADE,
    event_id        UUID NOT NULL,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL
                    CHECK (status IN ('pending', 'delivering', 'delivered', 'exhausted')),
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX webhook_deliveries_claim_idx ON webhook_deliveries (next_attempt_at)
    WHERE status = 'pending';
CREATE INDEX webhook_deliveries_business_idx ON webhook_deliveries (business_id, created_at DESC);

-- updated_at maintenance, so no handler has to remember.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER businesses_set_updated_at BEFORE UPDATE ON businesses
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER api_keys_set_updated_at BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER customers_set_updated_at BEFORE UPDATE ON customers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER invoices_set_updated_at BEFORE UPDATE ON invoices
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER payment_attempts_set_updated_at BEFORE UPDATE ON payment_attempts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER idempotency_keys_set_updated_at BEFORE UPDATE ON idempotency_keys
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER webhook_endpoints_set_updated_at BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER webhook_deliveries_set_updated_at BEFORE UPDATE ON webhook_deliveries
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
