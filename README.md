# Invoice & Payment Service

A minimal invoice and payment service: a business creates invoices, customers
pay them through a payment processor, and the business is told about it via
signed webhooks. Rust (Axum), PostgreSQL 16 with row-level security, a
transactional outbox, and a mock PSP with two providers.

| Document | What it's for |
|---|---|
| [DESIGN.md](DESIGN.md) | **The primary deliverable.** Data model, state machine, payment correctness and failure modes, webhooks, auth, permissions + RLS, what was cut. |
| [AI_USAGE.md](AI_USAGE.md) | How AI was used, three decisions made against or independent of it, and what it got wrong. |
| [API_EXAMPLES.md](API_EXAMPLES.md) | A copy-paste curl tour of the whole API, in usage order, including every failure mode. |
| [openapi.yaml](openapi.yaml) | OpenAPI 3.1 spec. Rendered as an interactive reference at [docs/api.html](docs/api.html) (`./scripts/build-docs.sh` regenerates it). |

## Demo Video

- Part 1 — architecture and live demo: https://www.loom.com/share/760f8b0610324128a0cfbe4aa77370e3
- Part 2 — state machine and failure-mode walkthrough: https://www.loom.com/share/2b7cc3d98320463c824a808354df36fa

## Run it

Requires Docker. Nothing else.

```bash
docker compose up --build
```

That brings up three containers with no manual steps: `db` (Postgres 16),
`mock-psp`, and `api`. The API runs migrations, applies the RLS policies, and
listens on **http://localhost:58080**. The mock PSP is on `:59090` and Postgres
on `:55432` (non-default ports so they don't collide with anything local).

```bash
curl localhost:58080/healthz
```

A demo business and three API keys are seeded so you can curl immediately:

| Key | Permissions |
|---|---|
| `sk_prod_demofull000000000000000000000001` | `*:*` |
| `sk_prod_demoread000000000000000000000002` | `*:read` |
| `sk_prod_democoll000000000000000000000003` | `invoice:read`, `payment:create` — can charge an invoice and nothing else |

## Four requests

```bash
export BASE=http://localhost:58080
export FULL=sk_prod_demofull000000000000000000000001
export COLL=sk_prod_democoll000000000000000000000003
```

**1. Create a customer**

```bash
curl -s $BASE/customers -H "Authorization: Bearer $FULL" \
  -H 'content-type: application/json' \
  -d '{"name":"Ada Lovelace","email":"ada@example.com"}'
```

**2. Create and send an invoice** — the server computes the total from the
line items; a client-supplied total is never accepted. Invoices start as
`draft`; `send` moves them to `sent`, which is the only payable state.

```bash
curl -s $BASE/invoices -H "Authorization: Bearer $FULL" \
  -H 'content-type: application/json' \
  -d '{"customer_id":"cus_...","due_date":"2026-10-01",
       "line_items":[{"description":"Widgets","quantity":3,"unit_amount_cents":1500}]}'

curl -s -X POST $BASE/invoices/inv_.../send -H "Authorization: Bearer $FULL"
```

**3. Pay it — success.** `Idempotency-Key` is required. Replaying the same
key returns the same response without a second charge.

```bash
curl -s $BASE/invoices/inv_.../pay -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' -H 'Idempotency-Key: pay-001' \
  -d '{"card_token":"tok_success"}'
```

**4. Pay it — declined.** A definitive decline is a `402`; the invoice stays
`sent` and payable with another card.

```bash
curl -s $BASE/invoices/inv_.../pay -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' -H 'Idempotency-Key: pay-002' \
  -d '{"card_token":"tok_card_declined"}'
```

[API_EXAMPLES.md](API_EXAMPLES.md) continues from here: the timeout and
network-error cases (`202`, reconciled in the background), the JWT tier for
secret-minting endpoints, webhook registration and signature verification,
and the permission model.

### Mock PSP card tokens

| Token | Behaviour |
|---|---|
| `tok_success` | succeeds after ~100 ms |
| `tok_insufficient_funds`, `tok_card_declined` | definitive decline after ~100 ms |
| `tok_timeout` | sleeps 30 s, then succeeds — the API returns `202` at 5 s and the reconciler settles it |
| `tok_network_error` | drops the connection — `202`, retried, eventually fails cleanly |

Pass `"processor": "betapay"` to route through the second mock provider,
which has a deliberately different wire format.

## Tests

Integration tests run against the real Postgres and mock PSP:

```bash
docker compose up -d db mock-psp
cargo test --workspace
```

The three tests the assignment asks for, plus the ones the security model
needed:

- `crates/api/tests/concurrency.rs` — 20 concurrent `POST /pay` on one
  invoice: exactly one succeeds, one charge at the PSP, consistent final state.
- `crates/api/tests/idempotency.rs` — same key replays the same response with
  no second PSP call; same key with a different body is a 422.
- `crates/api/tests/psp_failure.rs` — `tok_timeout` doesn't hang the caller,
  `tok_network_error` leaves nothing corrupted, the reconciler resolves an
  unknown outcome without charging twice, and gives up loudly after its cap.
- `crates/api/tests/permissions.rs`, `permissions_rls.rs` — scope enforcement,
  no-escalation minting, and proof that RLS alone blocks cross-tenant reads
  (a query with its `WHERE business_id` removed still returns nothing).

Unit tests cover the state machine exhaustively, money arithmetic, the
permission grammar (with a Rust-vs-SQL drift pin), key hashing, and webhook
signing. Broad handler coverage is deliberately skipped; the tests above
exercise the parts where a bug costs money.

## Layout

```
crates/api/            the service
  src/auth/            api keys, jwt, permissions (the route→scope table)
  src/routes/          handlers; payments.rs is the three-phase pay path
  src/domain/          state_machine.rs, money.rs, ids.rs
  src/psp/             PaymentProcessor trait + alphapay/betapay adapters
  src/outbox.rs        webhook dispatcher
  src/reconciler.rs    pending-attempt sweeper
  sql/rls.sql          grants, auth helpers, every RLS policy (re-applied on boot)
  tests/               integration tests
crates/mock-psp/       the mock provider (two wire formats, idempotency ledger)
migrations/            roles, schema, seed
```
