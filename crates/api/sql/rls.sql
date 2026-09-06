/* ==========================================================================
 * Grants, auth helper functions, and row-level security policies.
 *
 * This file is NOT a versioned migration. It is re-applied in full on every
 * boot, after `sqlx migrate run`. Policies are declarative: the right way to
 * change one is to edit it here and redeploy, not to accumulate a chain of
 * ALTER POLICY migrations you then have to read backwards to know the current
 * state. Everything here is written to be idempotent.
 *
 * The model:
 *   - invoice_app sees exactly one business's rows, and only for the scopes
 *     its credential carries. Both halves are enforced *here*, in the policy,
 *     not in the handler. A handler that forgets its WHERE clause returns
 *     nothing; a read-only key that reaches an INSERT dies at the policy, and
 *     so does a create-only key that reaches a revoke.
 *   - invoice_service is the background worker role. Its access is
 *     deliberately cross-tenant, which is why it is a separate role with
 *     separate policies on a short list of tables.
 * ========================================================================== */

/* ==========================================================================
 * AUTH HELPERS
 *
 * Everything reads from one transaction-local GUC, request.jwt.claims, set by
 * db/tenant.rs at the top of every request transaction.
 * 
 * The model:
 *   - For JWT-authenticated requests the GUC is the token's real claims.
 *   - For API-key requests it is a synthesised claims document of the same shape.
 *     (one shape means one set of helpers).
 * ========================================================================== */

CREATE OR REPLACE FUNCTION app_claims() RETURNS jsonb
    SECURITY DEFINER SET search_path = public AS $$
    SELECT NULLIF(current_setting('request.jwt.claims', true), '')::jsonb;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION app_business_id() RETURNS uuid
    SECURITY DEFINER SET search_path = public AS $$
    SELECT (app_claims() -> 'claims' ->> 'business_id')::uuid;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION app_permissions() RETURNS text[]
    SECURITY DEFINER SET search_path = public AS $$
    SELECT COALESCE(
        ARRAY(SELECT jsonb_array_elements_text(app_claims() -> 'claims' -> 'permissions')),
        ARRAY[]::text[]
    );
$$ LANGUAGE sql STABLE;

/* Credential tier. 'critical' is only ever minted onto a short-lived JWT
 * (see POST /auth/tokens); a long-lived API key can never present it. Policies
 * on secret-generating tables require it, so a leaked API key - even a '*:*'
 * one - cannot mint further credentials without the extra, loggable,
 * revocable token-mint step. */
CREATE OR REPLACE FUNCTION app_tier() RETURNS text
    SECURITY DEFINER SET search_path = public AS $$
    SELECT COALESCE(app_claims() -> 'claims' ->> 'tier', 'none');
$$ LANGUAGE sql STABLE;

/* has_scope - authoritative definition of the permission grammar.
 *
 * Permissions are 'resource:action' strings ('*' allowed on either side).
 * A check passes iff the credential's set intersects the strings that grant
 * it. Grants are purely additive - no deny rules, so absence = denial.
 *
 * Actions: read, create, update, delete.
 */
CREATE OR REPLACE FUNCTION has_scope(res text, act text) RETURNS boolean
    SECURITY DEFINER SET search_path = public AS $$
    SELECT app_permissions() && CASE
        WHEN act = 'read' THEN ARRAY[
            res || ':read', res || ':create', res || ':update', res || ':delete',
            res || ':*',
            '*:read', '*:create', '*:update', '*:delete', '*:*'
        ]
        ELSE ARRAY[res || ':' || act, res || ':*', '*:' || act, '*:*']
    END;
$$ LANGUAGE sql STABLE;

/* lookup_api_key - solves the chicken-and-egg of authentication.
 *
 * The auth middleware has to read api_keys to discover which tenant is
 * calling, but tenant context is exactly what it does not have yet. So
 * api_keys grants invoice_app no SELECT at all, and this SECURITY DEFINER
 * function is the single hole in that wall: it takes a prefix and a hash,
 * and returns the tenant and scopes for a live key or nothing. It cannot be
 * used to enumerate keys, and it never returns the hash. */
CREATE OR REPLACE FUNCTION lookup_api_key(p_prefix text, p_hash text)
    RETURNS TABLE (id uuid, business_id uuid, permissions text[])
    SECURITY DEFINER SET search_path = public AS $$
    SELECT k.id, k.business_id, k.permissions
    FROM api_keys k
    WHERE k.key_prefix = p_prefix
      AND k.key_hash = p_hash
      AND k.revoked_at IS NULL;
$$ LANGUAGE sql STABLE;

/* Touching last_used_at is a write on a deny-by-default table, so it also goes
 * through a definer function. Best-effort telemetry, never on the hot path. */
CREATE OR REPLACE FUNCTION touch_api_key(p_id uuid) RETURNS void
    SECURITY DEFINER SET search_path = public AS $$
    UPDATE api_keys SET last_used_at = now() WHERE id = p_id;
$$ LANGUAGE sql VOLATILE;

/* active_webhook_endpoints - endpoint discovery for event emission.
 *
 * Emitting an event is a *system* action triggered by a caller, not an action
 * the caller performs on webhooks. A payment-collector key holding
 * ['invoice:read', 'payment:create'] must be able to pay an invoice - which
 * emits invoice.paid - without holding webhook:read, which would let it
 * enumerate where its tenant's events are delivered.
 *
 * So this bypasses the webhook:read policy, and gives up nothing to do it: it
 * takes no arguments (the tenant comes from the request claims, so it cannot
 * be pointed at another business) and returns only ids, never URLs or
 * secrets. */
CREATE OR REPLACE FUNCTION active_webhook_endpoints()
    RETURNS TABLE (id uuid, business_id uuid)
    SECURITY DEFINER SET search_path = public AS $$
    SELECT e.id, e.business_id
    FROM webhook_endpoints e
    WHERE e.business_id = app_business_id()
      AND e.disabled_at IS NULL;
$$ LANGUAGE sql STABLE;

REVOKE ALL ON FUNCTION lookup_api_key(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION touch_api_key(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION active_webhook_endpoints() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_api_key(text, text) TO invoice_app;
GRANT EXECUTE ON FUNCTION touch_api_key(uuid) TO invoice_app;
GRANT EXECUTE ON FUNCTION active_webhook_endpoints() TO invoice_app;

/* ==========================================================================
 * GRANTS
 *
 * Start from zero every time, then add back exactly what each role needs.
 * Re-applying this file therefore removes a grant that was deleted from it,
 * which a pile of incremental migrations would not.
 * ========================================================================== */

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM invoice_app, invoice_service;

GRANT USAGE ON SCHEMA public TO invoice_app, invoice_service;

GRANT SELECT, INSERT, UPDATE ON
    customers,
    invoices,
    invoice_line_items,
    payment_attempts,
    idempotency_keys,
    webhook_endpoints,
    webhook_deliveries
TO invoice_app;

/* api_keys: SELECT and the two writes are granted, but every one of them is
 * gated by a policy below. There is no DELETE anywhere - revocation is
 * `revoked_at = now()`, because "which credential was live when this happened"
 * is a question you get asked after an incident. */
GRANT SELECT, INSERT, UPDATE ON api_keys TO invoice_app;

/* businesses is read-only to the app; tenant creation is an operator action
 * (see DESIGN.md "what I cut": no business-bootstrap API in v1). */
GRANT SELECT ON businesses TO invoice_app;

/* The background worker touches four tables and nothing else. It can settle
 * payment attempts, read the invoices it is settling, deliver webhooks, and
 * read the endpoint secrets it needs to sign them. It cannot read customers,
 * it cannot read api_keys, and it cannot create invoices. */
GRANT SELECT, UPDATE ON payment_attempts TO invoice_service;
GRANT SELECT, UPDATE ON invoices TO invoice_service;
GRANT SELECT, INSERT, UPDATE ON webhook_deliveries TO invoice_service;
GRANT SELECT ON webhook_endpoints TO invoice_service;

/* ==========================================================================
 * POLICY FACTORY
 *
 * One function, applied per table. One policy per command rather than a
 * single FOR ALL policy, because SELECT, INSERT and UPDATE need *different
 * scopes* - that is the whole point of having read, create and update as
 * separate actions. Everything is dropped and recreated so this file can run
 * on every boot.
 *
 * The factory covers the plain case: a table whose three commands map onto
 * read/create/update of one resource. A table that soft-deletes, or that two
 * resources write, is hand-rolled below.
 * ========================================================================== */

CREATE OR REPLACE FUNCTION apply_tenant_policy(target_table text, resource text)
    RETURNS void AS $$
BEGIN
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY;', target_table);
    /* FORCE so that even a connection that happens to own the table is still
     * filtered. Superusers still bypass RLS - that is what makes the migrator
     * able to seed - but nothing else does. */
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY;', target_table);

    EXECUTE format('DROP POLICY IF EXISTS %I ON %I;', target_table || '_app_select', target_table);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I;', target_table || '_app_insert', target_table);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I;', target_table || '_app_update', target_table);

    EXECUTE format(
        'CREATE POLICY %I ON %I FOR SELECT TO invoice_app
            USING (business_id = app_business_id() AND has_scope(%L, ''read''));',
        target_table || '_app_select', target_table, resource);

    EXECUTE format(
        'CREATE POLICY %I ON %I FOR INSERT TO invoice_app
            WITH CHECK (business_id = app_business_id() AND has_scope(%L, ''create''));',
        target_table || '_app_insert', target_table, resource);

    /* USING and WITH CHECK are both required and both say the same thing: you
     * may only touch your own rows, and you may not move a row out of your
     * tenant on the way past. */
    EXECUTE format(
        'CREATE POLICY %I ON %I FOR UPDATE TO invoice_app
            USING (business_id = app_business_id() AND has_scope(%L, ''update''))
            WITH CHECK (business_id = app_business_id() AND has_scope(%L, ''update''));',
        target_table || '_app_update', target_table, resource, resource);
END;
$$ LANGUAGE plpgsql;

REVOKE ALL ON FUNCTION apply_tenant_policy(text, text) FROM PUBLIC;

SELECT apply_tenant_policy('customers', 'customer');
SELECT apply_tenant_policy('invoice_line_items', 'invoice');
SELECT apply_tenant_policy('webhook_endpoints', 'webhook');

/* ==========================================================================
 * TABLES WITH THEIR OWN RULES
 * ========================================================================== */

/* invoices: written by two different scopes, so this one is hand-rolled
 * rather than taken from the factory.
 *
 * Settling a payment writes the invoice - amount_paid_cents and the state
 * column both move - and a payment-collector credential holding
 * ['invoice:read', 'payment:create'] must be able to do that without also
 * being able to author, send or void invoices. So UPDATE accepts either
 * invoice:update or payment:create, while INSERT stays strictly
 * invoice:create.
 *
 * payment:create rather than payment:update is the right half of that pair
 * because the invoice write is part of *making* a payment: the whole charge -
 * insert the attempt, settle it, move the invoice - is one operation, and it
 * is the operation POST /invoices/{id}/pay performs.
 *
 * This is also what makes `SELECT ... FOR UPDATE` work for the collector.
 * Postgres checks the UPDATE policy's USING clause on a locking read, not just
 * the SELECT policy - so under an invoice:update-only UPDATE policy the
 * payment path's row lock would silently return no rows and the caller would
 * get a 404 for an invoice they can plainly read. Worth knowing about; it is
 * the kind of RLS behaviour that looks like a missing row rather than a denied
 * write. */
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS invoices_app_select ON invoices;
DROP POLICY IF EXISTS invoices_app_insert ON invoices;
DROP POLICY IF EXISTS invoices_app_update ON invoices;

CREATE POLICY invoices_app_select ON invoices FOR SELECT TO invoice_app
    USING (business_id = app_business_id() AND has_scope('invoice', 'read'));

CREATE POLICY invoices_app_insert ON invoices FOR INSERT TO invoice_app
    WITH CHECK (business_id = app_business_id() AND has_scope('invoice', 'create'));

CREATE POLICY invoices_app_update ON invoices FOR UPDATE TO invoice_app
    USING (business_id = app_business_id()
           AND (has_scope('invoice', 'update') OR has_scope('payment', 'create')))
    WITH CHECK (business_id = app_business_id()
                AND (has_scope('invoice', 'update') OR has_scope('payment', 'create')));

/* payment_attempts: reads follow invoice:read (an attempt is part of the
 * invoice's story), writes require a payment scope. This is why the factory
 * takes one resource and this table does not use it - a collector key holding
 * ['invoice:read', 'payment:create'] must be able to do both halves.
 *
 * UPDATE accepts payment:create as well as payment:update because the sync
 * charge path settles the attempt it just inserted, in the same transaction
 * (routes/payments.rs: `UPDATE payment_attempts SET status = 'succeeded'`).
 * That settlement is the second half of the create, not a separate power, and
 * gating it on payment:update would mean no credential could complete a charge
 * without also being able to rewrite historical attempts. payment:update is
 * still accepted on its own, for a credential whose job is reconciliation
 * rather than collection. */
ALTER TABLE payment_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_attempts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS payment_attempts_app_select ON payment_attempts;
DROP POLICY IF EXISTS payment_attempts_app_insert ON payment_attempts;
DROP POLICY IF EXISTS payment_attempts_app_update ON payment_attempts;
DROP POLICY IF EXISTS payment_attempts_service_all ON payment_attempts;

CREATE POLICY payment_attempts_app_select ON payment_attempts FOR SELECT TO invoice_app
    USING (business_id = app_business_id()
           AND (has_scope('invoice', 'read') OR has_scope('payment', 'read')));

CREATE POLICY payment_attempts_app_insert ON payment_attempts FOR INSERT TO invoice_app
    WITH CHECK (business_id = app_business_id() AND has_scope('payment', 'create'));

CREATE POLICY payment_attempts_app_update ON payment_attempts FOR UPDATE TO invoice_app
    USING (business_id = app_business_id()
           AND (has_scope('payment', 'create') OR has_scope('payment', 'update')))
    WITH CHECK (business_id = app_business_id()
                AND (has_scope('payment', 'create') OR has_scope('payment', 'update')));

/* The reconciler settles attempts across all tenants. */
CREATE POLICY payment_attempts_service_all ON payment_attempts FOR ALL TO invoice_service
    USING (true) WITH CHECK (true);

/* invoices additionally need a service policy: settling a payment writes the
 * invoice too. */
DROP POLICY IF EXISTS invoices_service_all ON invoices;
CREATE POLICY invoices_service_all ON invoices FOR ALL TO invoice_service
    USING (true) WITH CHECK (true);

/* idempotency_keys is infrastructure, not a resource. It carries no scope
 * check of its own - the endpoint that uses it already enforced one - but it
 * is still tenant-scoped, so one business can never observe or collide with
 * another's keys. */
ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS idempotency_keys_app_all ON idempotency_keys;
CREATE POLICY idempotency_keys_app_all ON idempotency_keys FOR ALL TO invoice_app
    USING (business_id = app_business_id())
    WITH CHECK (business_id = app_business_id());

/* webhook_endpoints: the factory gave it the plain read/create/update trio.
 * Two of those need replacing.
 *
 * Creating an endpoint mints a signing secret, so INSERT additionally requires
 * the critical tier.
 *
 * UPDATE is gated on webhook:delete, not webhook:update, because the only
 * UPDATE the app ever issues against this table *is* the delete: disabling an
 * endpoint is `disabled_at = now()` (routes/webhooks.rs), since a hard DELETE
 * would take the delivery history with it. The scope names the operation the
 * caller is performing, not the SQL verb it happens to be spelled with - a key
 * granted webhook:update would otherwise silently be able to switch off its
 * tenant's event delivery. */
DROP POLICY IF EXISTS webhook_endpoints_app_insert ON webhook_endpoints;
CREATE POLICY webhook_endpoints_app_insert ON webhook_endpoints FOR INSERT TO invoice_app
    WITH CHECK (business_id = app_business_id()
                AND has_scope('webhook', 'create')
                AND app_tier() = 'critical');

DROP POLICY IF EXISTS webhook_endpoints_app_update ON webhook_endpoints;
CREATE POLICY webhook_endpoints_app_update ON webhook_endpoints FOR UPDATE TO invoice_app
    USING (business_id = app_business_id()
           AND has_scope('webhook', 'delete')
           AND app_tier() = 'critical')
    WITH CHECK (business_id = app_business_id()
                AND has_scope('webhook', 'delete')
                AND app_tier() = 'critical');

DROP POLICY IF EXISTS webhook_endpoints_service_select ON webhook_endpoints;
CREATE POLICY webhook_endpoints_service_select ON webhook_endpoints FOR SELECT TO invoice_service
    USING (true);

/* webhook_deliveries: the app inserts outbox rows in the same transaction as
 * the state change that produced them, so INSERT is gated on the scopes for
 * the *state changes that emit events* rather than on a webhook scope: an
 * invoice being created, an invoice being sent or voided, and a payment being
 * taken (see the events::emit call sites). Reading the delivery log is
 * webhook:read. The dispatcher owns everything else. */
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS webhook_deliveries_app_select ON webhook_deliveries;
DROP POLICY IF EXISTS webhook_deliveries_app_insert ON webhook_deliveries;
DROP POLICY IF EXISTS webhook_deliveries_service_all ON webhook_deliveries;

CREATE POLICY webhook_deliveries_app_select ON webhook_deliveries FOR SELECT TO invoice_app
    USING (business_id = app_business_id() AND has_scope('webhook', 'read'));

CREATE POLICY webhook_deliveries_app_insert ON webhook_deliveries FOR INSERT TO invoice_app
    WITH CHECK (business_id = app_business_id()
                AND (has_scope('invoice', 'create')
                     OR has_scope('invoice', 'update')
                     OR has_scope('payment', 'create')));

CREATE POLICY webhook_deliveries_service_all ON webhook_deliveries FOR ALL TO invoice_service
    USING (true) WITH CHECK (true);

/* api_keys: reading key *metadata* (never the hash) is ordinary api_key:read.
 * Creating or revoking one is the highest-privilege operation in the system,
 * so each requires the critical tier on top of its scope. A stolen '*:*' API
 * key therefore cannot mint itself a successor.
 *
 * As with webhook_endpoints, revocation is a soft delete - `revoked_at =
 * now()`, because "which credential was live when this happened" is a question
 * you get asked after an incident - so the UPDATE policy is gated on
 * api_key:delete. Splitting it from api_key:create is worth something real: a
 * provisioning job can now be allowed to issue keys without also being able to
 * revoke every other key the tenant holds, and an incident-response credential
 * can be allowed to revoke without being able to mint. */
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS api_keys_app_select ON api_keys;
DROP POLICY IF EXISTS api_keys_app_insert ON api_keys;
DROP POLICY IF EXISTS api_keys_app_update ON api_keys;

CREATE POLICY api_keys_app_select ON api_keys FOR SELECT TO invoice_app
    USING (business_id = app_business_id() AND has_scope('api_key', 'read'));

CREATE POLICY api_keys_app_insert ON api_keys FOR INSERT TO invoice_app
    WITH CHECK (business_id = app_business_id()
                AND has_scope('api_key', 'create')
                AND app_tier() = 'critical');

CREATE POLICY api_keys_app_update ON api_keys FOR UPDATE TO invoice_app
    USING (business_id = app_business_id()
           AND has_scope('api_key', 'delete')
           AND app_tier() = 'critical')
    WITH CHECK (business_id = app_business_id()
                AND has_scope('api_key', 'delete')
                AND app_tier() = 'critical');

/* businesses: you can read your own row and nothing else. No scope gate - if
 * you authenticated at all, you are allowed to know who you are. */
ALTER TABLE businesses ENABLE ROW LEVEL SECURITY;
ALTER TABLE businesses FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS businesses_app_select ON businesses;
CREATE POLICY businesses_app_select ON businesses FOR SELECT TO invoice_app
    USING (id = app_business_id());
