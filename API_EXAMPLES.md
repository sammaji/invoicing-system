# API Examples

A copy-paste tour of the whole API against a local `docker compose up`, in the
order you'd actually use it. Full request/response shapes are in
[openapi.yaml](openapi.yaml).

- API: `http://localhost:58080`
- Mock PSP: `http://localhost:59090` (you never call it directly; its admin
  endpoints are used below to *prove* no double-charging)

The seed migration creates a demo business with three API keys, so there is no
bootstrap step:

| Key | Permissions | Exists to show |
|---|---|---|
| `sk_prod_demofull000000000000000000000001` | `*:*` | everything |
| `sk_prod_demoread000000000000000000000002` | `*:read` | a read-only credential |
| `sk_prod_democoll000000000000000000000003` | `invoice:read`, `payment:create` | least privilege: can charge an invoice, cannot touch anything else |

Set them up once for the session:

```bash
export BASE=http://localhost:58080
export FULL=sk_prod_demofull000000000000000000000001
export READ=sk_prod_demoread000000000000000000000002
export COLL=sk_prod_democoll000000000000000000000003
```

---

## 1. Health

```bash
curl $BASE/healthz
```

## 2. Create a customer

```bash
curl -s $BASE/customers \
  -H "Authorization: Bearer $FULL" \
  -H 'content-type: application/json' \
  -d '{"name": "Ada Lovelace", "email": "ada@example.com"}'
```

```json
{
  "id": "cus_01a07835e785718294ecd23b7823e396",
  "object": "customer",
  "name": "Ada Lovelace",
  "email": "ada@example.com",
  "created_at": "2026-09-06T19:33:13.732958Z"
}
```

Keep the id around:

```bash
export CUS=cus_01a07835e785718294ecd23b7823e396
```

The permission model in one request — the read-only key gets a 403 that names
the missing scope:

```bash
curl -s $BASE/customers \
  -H "Authorization: Bearer $READ" \
  -H 'content-type: application/json' \
  -d '{"name": "Eve", "email": "eve@example.com"}'
```

```json
{ "error": { "type": "missing_permission",
             "message": "missing permission customer:create",
             "missing_permission": "customer:create", "status": 403 } }
```

## 3. Create an invoice (server computes the total)

The request carries line items only. `total_cents` is computed server-side
(3 × 1500 + 1 × 2500 = 7000); a client-supplied total is never accepted.

```bash
curl -s $BASE/invoices \
  -H "Authorization: Bearer $FULL" \
  -H 'content-type: application/json' \
  -d '{
    "customer_id": "'$CUS'",
    "due_date": "2026-10-01",
    "line_items": [
      {"description": "Widgets",  "quantity": 3, "unit_amount_cents": 1500},
      {"description": "Shipping", "quantity": 1, "unit_amount_cents": 2500}
    ]
  }'
```

The invoice is created in `draft` with `"total_cents": 7000`.

```bash
export INV=inv_01a07835fbdf7042a3bd5a3250d8f303   # from the response
```

## 4. The state machine says no

A draft cannot be paid — it has never been sent to anyone:

```bash
curl -s $BASE/invoices/$INV/pay \
  -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: demo-draft-pay' \
  -d '{"card_token": "tok_success"}'
```

```json
{ "error": { "type": "invalid_state_transition",
             "message": "cannot pay an invoice in state draft",
             "current_state": "draft", "attempted_transition": "pay",
             "status": 409 } }
```

## 5. Send it

```bash
curl -s -X POST $BASE/invoices/$INV/send -H "Authorization: Bearer $FULL"
```

State is now `sent`; an `invoice.sent` webhook is queued in the same
transaction.

## 6. Pay it — success

Note this uses the **collector** key, which holds only
`invoice:read, payment:create`. `Idempotency-Key` is **required**.

```bash
curl -s $BASE/invoices/$INV/pay \
  -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: pay-ada-001' \
  -d '{"card_token": "tok_success"}'
```

`200` — the payment attempt, with the updated invoice embedded:

```json
{
  "id": "pa_...", "object": "payment_attempt",
  "status": "succeeded", "processor": "alphapay",
  "amount_cents": 7000, "psp_ref": "alphapay_ref_...",
  "invoice": { "id": "inv_...", "state": "paid",
               "amount_paid_cents": 7000, "amount_remaining_cents": 0, "...": "..." }
}
```

## 7. Idempotency, all three cases

**Replay** (same key, same body) returns the stored response byte-for-byte —
the PSP is not called again:

```bash
curl -s $BASE/invoices/$INV/pay \
  -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: pay-ada-001' \
  -d '{"card_token": "tok_success"}'
```

**Reuse with a different body** is a 422 — replaying would hide a caller bug,
charging again would be worse:

```bash
curl -s $BASE/invoices/$INV/pay \
  -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: pay-ada-001' \
  -d '{"card_token": "tok_card_declined"}'
```

```json
{ "error": { "type": "idempotency_key_reuse",
             "message": "Idempotency-Key `pay-ada-001` was already used with a different request body",
             "status": 422 } }
```

**A fresh key against the already-paid invoice** is a 409:

```bash
curl -s $BASE/invoices/$INV/pay \
  -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: pay-ada-002' \
  -d '{"card_token": "tok_success"}'
```

```json
{ "error": { "type": "invoice_already_paid",
             "message": "this invoice has already been paid in full", "status": 409 } }
```

## 8. Pay — declined

(Create + send a fresh invoice as in §3/§5 first.) A definitive decline is a
`402`; the invoice is untouched — still `sent`, still payable with another
card:

```bash
curl -s $BASE/invoices/$INV2/pay \
  -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: pay-decl-001' \
  -d '{"card_token": "tok_card_declined"}'
```

```json
{ "error": { "type": "payment_failed", "message": "payment failed: card_declined",
             "code": "card_declined", "payment_attempt_id": "pa_...", "status": 402 } }
```

An `invoice.payment_failed` webhook is queued.

## 9. Pay — the PSP goes dark

`tok_timeout` makes the PSP sleep 30 s; the service gives up at 5 s and tells
the truth — outcome unknown, `202`:

```bash
curl -s -w '\nHTTP %{http_code} in %{time_total}s\n' $BASE/invoices/$INV3/pay \
  -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: pay-tmo-001' \
  -d '{"card_token": "tok_timeout"}'
```

```json
{
  "id": "pa_...", "status": "pending", "...": "...",
  "invoice": { "state": "sent", "...": "..." },
  "message": "the payment processor did not return a definitive outcome; this attempt is being reconciled and will settle on its own. Poll GET /invoices/{id} for the result."
}
```

Do **not** retry with a new idempotency key — the original charge may still
succeed. The background reconciler re-submits the same reference to the same
processor (which deduplicates), and within ~a minute:

```bash
curl -s $BASE/invoices/$INV3 -H "Authorization: Bearer $COLL"
```

…the attempt is `succeeded` and the invoice `paid` — with exactly **one**
charge at the PSP. `tok_network_error` behaves the same way, except the
reconciler's retries keep failing and eventually mark the attempt `failed`
(`failure_code: reconciliation_exhausted`) instead of leaving it stuck.

Proof of the single charge, from the mock PSP's admin surface:

```bash
curl -s http://localhost:59090/admin/charges
```

## 10. A second processor

Two mock providers with deliberately different wire formats sit behind the
same interface. `betapay`'s `DECLINED_NSF` is normalised to the same
`insufficient_funds` you'd get from `alphapay`:

```bash
curl -s $BASE/invoices/$INV2/pay \
  -H "Authorization: Bearer $COLL" \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: pay-beta-001' \
  -d '{"card_token": "tok_insufficient_funds", "processor": "betapay"}'
```

## 11. Query invoices

```bash
curl -s "$BASE/invoices?state=paid" -H "Authorization: Bearer $READ"
```

```bash
curl -s "$BASE/invoices?overdue=true" -H "Authorization: Bearer $READ"
```

```bash
curl -s "$BASE/invoices?customer_id=$CUS&limit=10" -H "Authorization: Bearer $READ"
```

`overdue` is computed at read time (collectible + past due date), so it can
never disagree with the calendar. Lists are cursor-paginated: pass the last
id of a page as `starting_after`.

## 12. Minting tokens

Secret-creating endpoints (`POST /api_keys`, `POST /webhook_endpoints`, and
their DELETEs) refuse plain API keys:

```bash
curl -s $BASE/webhook_endpoints \
  -H "Authorization: Bearer $FULL" \
  -H 'content-type: application/json' \
  -d '{"url": "http://host.docker.internal:58099/hook"}'
```

```json
{ "error": { "type": "jwt_required",
             "message": "POST /webhook_endpoints requires a short-lived token from POST /auth/tokens; a long-lived API key cannot be used here",
             "status": 403 } }
```

Mint a 15-minute token instead — optionally narrowed to just the scopes the
job needs:

```bash
export TOKEN=$(curl -s $BASE/auth/tokens \
  -H "Authorization: Bearer $FULL" \
  -H 'content-type: application/json' \
  -d '{"permissions": ["webhook:create", "api_key:create", "*:read"]}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
```

Minting can only *narrow*: asking for a scope the key doesn't hold is a 403.

## 13. Webhooks

Register an endpoint with the token. The signing `secret` is returned **once**:

```bash
curl -s $BASE/webhook_endpoints \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"url": "http://host.docker.internal:58099/hook"}'
```

```json
{ "id": "whe_...", "object": "webhook_endpoint",
  "url": "http://host.docker.internal:58099/hook",
  "secret": "whsec_...", "created_at": "..." }
```

Every event arrives as a `POST` with:

```
Webhook-Id:        evt_...          (stable across retries — deduplicate on it)
Webhook-Timestamp: 1788723178
Webhook-Signature: v1=<hex HMAC-SHA256(secret, "{timestamp}.{raw body}")>
```

Verification recipe (reject timestamps older than 5 minutes, compare in
constant time):

```python
import hmac, hashlib
expected = "v1=" + hmac.new(secret.encode(),
                            f"{timestamp}.{raw_body}".encode(),
                            hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, signature_header)
```

Failed deliveries are retried at ~5s, 30s, 2m, 10m, 30m, 2h (7 attempts,
jittered); after that they are `exhausted` — never silently dropped. Ask the
API what happened to any delivery:

```bash
curl -s "$BASE/webhook_deliveries?status=exhausted" -H "Authorization: Bearer $FULL"
```

```bash
curl -s "$BASE/webhook_deliveries?event_type=invoice.paid" -H "Authorization: Bearer $FULL"
```

## 14. API key lifecycle

Create a narrow key (requires the token from §12; the new key's permissions
must be a subset of the token's — no escalation path):

```bash
curl -s $BASE/api_keys \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name": "reporting job", "permissions": ["*:read"]}'
```

The plaintext `key` appears in this response only. List and revoke:

```bash
curl -s $BASE/api_keys -H "Authorization: Bearer $FULL"
```

```bash
curl -s -X DELETE $BASE/api_keys/ak_XXXX -H "Authorization: Bearer $TOKEN"
```

Revocation is immediate and soft (`revoked_at` is set, the row remains as
audit trail); the revoked key gets `401` on its next request.

## 15. Void

Void works only while no money has moved (`draft`/`sent`,
`amount_paid_cents = 0`):

```bash
curl -s -X POST $BASE/invoices/$INV4/void -H "Authorization: Bearer $FULL"
```

Voiding a paid invoice is a `409 invalid_state_transition` — money that has to
go back goes forward through a refund (designed, not built in v1), never by
erasing the document.

---

## Mock PSP card tokens

| Token | Behaviour |
|---|---|
| `tok_success` | ~100 ms, then success |
| `tok_insufficient_funds` | ~100 ms, definitive decline (`insufficient_funds`) |
| `tok_card_declined` | ~100 ms, definitive decline (`card_declined`) |
| `tok_timeout` | 30 s sleep, then success — the API answers `202` in ~5 s and reconciles |
| `tok_network_error` | connection dropped — `202`, reconciled, eventually fails cleanly |
| anything else | success |

Mock PSP admin surface (for demos/tests): `GET /admin/charges`,
`GET /admin/charges/{reference}`, `POST /admin/reset` on port `59090`.
