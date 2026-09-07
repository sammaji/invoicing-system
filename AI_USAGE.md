# AI usage

Claude code, Anthropic Opus 5 - for planning, ideation and writing code (reviewed
each step). Used Miro MCP for making diagrams.

## Three decisions I made against or independent of the AI

Each of these started as a concrete proposal in the first implementation
plan Claude wrote, and what shipped is different.

### RLS

The first plan enforced tenancy in the application. That works, and it is the version you can write
fastest. What it is not is a single source of truth. The rule gets *stated*
once in a design doc and *implemented* at every query site, so its correctness
is the conjunction of a few hundred independent implementations - and the set
only grows. The reporting job, the ops console, the backfill script, the next
service someone writes against this database: none of them inherit the rule,
each re-derives it, and a `psql` session inherits nothing at all. Isolation
between customers is not a property you want re-derived by every future caller.

RLS inverts that. Isolation becomes a property of the tables, declared once,
and every connection is subject to it whether or not the code on the other end
knows it exists. `crates/api/sql/rls.sql` is the entire security posture in one
readable file - grants, helper functions, policies - re-applied in full on
every boot from a `REVOKE ALL` baseline, so a line deleted from the file
actually disappears from the database. Reviewing "who can see what" is reading
one file rather than auditing every query in every consumer, and onboarding a
new consumer is handing it the `invoice_app` role.

It also turned out to be less code, not more. The policy set is one factory
function plus a handful of documented exceptions; the alternative is threading
a tenant parameter through every repository method in every service, forever.
And since the same claims document carries `permissions`, the scope check rides
in the same policy - `has_scope('invoice', 'read')` - so tenancy and permission
are enforced in one place, at the data, instead of being two application
concerns that have to stay in agreement.

Mechanically: `invoice_app` owns no tables and has no `BYPASSRLS`; every table
is `ENABLE` + `FORCE ROW LEVEL SECURITY`; policies read one transaction-local
setting, `request.jwt.claims`, set as the first statement of the transaction
and gone at `COMMIT`, so a pooled connection cannot carry one request's context
into the next. Handlers still write the filter out of hygiene, but it is no
longer the thing that is load-bearing - an integration test proves that by
running a query with the `WHERE` clause deliberately removed and getting
nothing back.

The cost is real and I paid it. Policies are per-command and carry different
scopes, and the `invoices` UPDATE policy has to accept `payment:create` as well
as `invoice:update` - otherwise the collector's `SELECT ... FOR UPDATE`
silently returns zero rows and the caller gets a `404` for an invoice it can
plainly read. That cost me an afternoon. In exchange, cross-tenant access is a
`404` with no code path of its own: the rows are not there.

Background work is the exception that proves the rule. The dispatcher and the
reconciler are legitimately cross-tenant, so they `SET LOCAL ROLE
invoice_service` for the life of one transaction, granted to `invoice_app`
`WITH INHERIT FALSE` so the request path never carries that reach ambiently.

### Indexable api keys

The proposal was the textbook one: hash the key, store the hash, store nothing
else. Right instinct about secrets, wrong data structure. Something has to be
indexed to find the row, and if the only stored value is the hash of the whole
key then either auth is a scan with a compare per row - `O(keys)` on the
hottest path in the service, growing with the customer base - or the hash
itself becomes the lookup index, which is exactly the value an attacker who
reaches the table wants to search by.

What shipped is `sk_prod_<8-char prefix><24-char secret>`. The prefix is stored
in the clear under a unique index, the SHA-256 of the full string is the
verifier, and the plaintext is returned exactly once. Authentication is one
index lookup plus one constant-time compare (`subtle::ConstantTimeEq`) - the
same cost at ten keys and at ten million. The prefix leaks nothing that
matters: it says *which* key, and the 24-character secret is still what proves
you hold it.

It also buys the operational half that hash-only cannot. A prefix is safe to
log, safe to show in a dashboard, safe to paste into a ticket ("revoke
`a7Kf2mQ1`"), and greppable across request logs after a suspected leak. With a
bare hash, nobody - including us - can go from a key fragment a customer reads
off their config to the row that needs revoking. Cost: one extra column and the
rule that prefixes are unique.

### Webhooks through a transactional outbox

The first pass sent the notification from the payment handler, `POST`ing to the
customer's endpoint once the transaction had committed. Two problems, and the
worse one is invisible. Calling out from the request path ties the p99 of
`POST /invoices/{id}/pay` to a stranger's server, and retrying there makes that
worse without fixing anything. Calling after `COMMIT` is a dual write: if the
process dies in the gap, the invoice is `paid` and nobody will ever be told,
and no amount of retry logic inside a dead process closes that window.

`events.rs` writes one `webhook_deliveries` row per live endpoint in the same
transaction as the state change. Either the invoice became paid and someone
will be told, or neither happened. Delivery is a separate loop that claims
batches with `FOR UPDATE SKIP LOCKED`, so running a second replica is a config
change rather than a redesign, and the retry schedule (5s to 2h, jittered,
seven attempts) lives entirely off the request path. `event_id` is stable across
every retry, so at-least-once is something receivers can actually deduplicate
against rather than a caveat in the docs, and an exhausted delivery stays
queryable at `GET /webhook_deliveries` instead of disappearing into a log line.

Endpoint discovery inside the emitting transaction is a `SECURITY DEFINER`
function returning ids only, because the credential causing the event often
should not be able to enumerate where events go - the seeded collector key
holds `invoice:read` and `payment:create` and nothing else.

## Things the AI proposed that I kept, but checked

- **SHA-256 for key hashing, not argon2.** Claude suggested this; I agreed
  only after doing the arithmetic. A 24-character secret from a 62-symbol
  alphabet is about 142 bits of entropy - there is nothing to guess, so a
  slow KDF would cost tens of milliseconds on every request to defend
  against an imaginary attack. What *does* matter is the constant-time
  compare (`subtle::ConstantTimeEq`, not `==`), which I added.
- **The partial unique index as the concurrency mechanism.** Proposed by
  Claude; I kept it because the alternatives it listed (advisory locks,
  SERIALIZABLE) genuinely fail the crash-during-charge case, and I could
  reproduce that reasoning without the notes.

## What the AI got wrong

**A real bug in generated code.** The list endpoints that `#[serde(flatten)]`
a shared `Pagination` struct returned `400 Failed to deserialize query
string` for any `?limit=` value. Serde's flatten buffers query values as
strings, and the `Option<i64>` field rejected `"25"`. The code was
plausible, compiled, and passed the tests that existed, because no test
paginated with a limit. It only appeared when we drove the API with curl.
The fix was a string-tolerant deserializer on that one field, plus tests
that actually pass `limit`.

Smaller ones from the same verification pass:
- An integration test asserted a strict `202` for the timeout case, but the
  test binary runs its tests concurrently and a neighbouring test's
  aggressive reconciler - cross-tenant by design - legitimately resolved the
  attempt first, so the request path correctly returned `200`. The test's
  expectation was wrong, not the service. It now accepts either honest
  outcome and asserts a single charge in both.
- It pinned the docs renderer to a CDN version whose bundle path 404'd.

**A design gap it didn't raise until asked.** When I asked what happens if a
customer pays, the reconciler gives up after its retry cap, and the
customer pays again, the answer was: the exhausted attempt is marked
`failed`, which releases the one-pending-per-invoice mutex, so a second
charge becomes possible while the first may have landed. The code logs this
as MANUAL REVIEW rather than preventing it. That's an honest handoff, but
it's a real window, and it's recorded in `DESIGN.md` because I'd rather a
reviewer see that I know where it is than find it themselves.
