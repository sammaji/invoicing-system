//! Permissions
//!
//! # Why scopes and not roles
//!
//! Roles work when credentials map onto people: "admin", "editor", "viewer"
//! are useful because an organisation actually has admins, editors and
//! viewers. These credentials are held by *machines*, and machines don't come
//! in tiers - they come in jobs. A payment-collection worker needs to read
//! invoices and charge them, and must never be able to create a customer. A
//! reporting job needs to read everything and write nothing. A CRM sync needs
//! full access to customers and nothing else.
//!
//! No fixed role set covers those three without either over-granting or
//! growing a role per integration. So a key carries its permissions directly:
//! a set of `resource:action` strings with `*` allowed on either side.
//!
//!   `["invoice:read", "payment:create"]`  the collector
//!   `["*:read"]`                          the reporting job
//!   `["customer:*"]`                      the CRM sync
//!   `["api_key:delete"]`                  the incident-response credential
//!   `["*:*"]`                             the bootstrap key
//!
//! Grants are additive and there are no deny rules, so absence is denial and
//! the order of the list never matters.

use crate::error::{AppError, AppResult};

pub const CUSTOMER: &str = "customer";
pub const INVOICE: &str = "invoice";
pub const PAYMENT: &str = "payment";
pub const WEBHOOK: &str = "webhook";
pub const API_KEY: &str = "api_key";

pub const RESOURCES: [&str; 5] = [CUSTOMER, INVOICE, PAYMENT, WEBHOOK, API_KEY];

pub const READ: &str = "read";
pub const CREATE: &str = "create";
pub const UPDATE: &str = "update";
pub const DELETE: &str = "delete";

pub const ACTIONS: [&str; 4] = [READ, CREATE, UPDATE, DELETE];

/// The three actions that change something, i.e. `ACTIONS` minus [`READ`].
///
/// Named because the read-implication rule in [`has_scope`] is defined over
/// exactly this set, and deriving it from `ACTIONS` at each call site is how
/// the SQL and Rust copies would drift apart the next time an action is added.
pub const MUTATING_ACTIONS: [&str; 3] = [CREATE, UPDATE, DELETE];

pub const WILDCARD: &str = "*";

/// True iff `permissions` grants `action` on `resource`.
///
/// **Every mutating action implies read on the same resource.** This is a real
/// rule of the model, not a shortcut, and Postgres is what forced the
/// question: RLS checks `INSERT ... RETURNING` against the *SELECT* policy as
/// well as the INSERT one, and `SELECT ... FOR UPDATE` against the *UPDATE*
/// policy as well as the SELECT one. A `customer:create`-only credential would
/// therefore be able to create a customer but not receive it back, and the
/// failure would surface as an inexplicable missing row rather than as a
/// permissions error.
///
/// So the model says what is actually true: a credential that may change a
/// resource may see it. The directions that carry the security value are
/// unaffected - a read-only key still cannot write anything, and a
/// `create`-only key still cannot delete.
///
/// The check is a set intersection, the same shape as the SQL `&&`, so the two
/// implementations are visibly the same rule rather than two rules that happen
/// to agree.
pub fn has_scope(permissions: &[String], resource: &str, action: &str) -> bool {
    let mut candidates = vec![
        format!("{resource}:{action}"),
        format!("{resource}:{WILDCARD}"),
        format!("{WILDCARD}:{action}"),
        format!("{WILDCARD}:{WILDCARD}"),
    ];

    if action == READ {
        for mutating in MUTATING_ACTIONS {
            candidates.push(format!("{resource}:{mutating}"));
            candidates.push(format!("{WILDCARD}:{mutating}"));
        }
    }

    permissions
        .iter()
        .any(|granted| candidates.iter().any(|c| c == granted))
}

/// Validate a permission list at the point it is granted.
///
/// Unknown resources are rejected rather than stored: a key created with
/// `["invoices:read"]` (note the plural) would otherwise authenticate fine and
/// then 403 on every request, and the caller would have no way to see why. A
/// 400 at creation with the valid list in the message costs one round trip and
/// saves an afternoon.
pub fn validate_permissions(permissions: &[String]) -> AppResult<()> {
    if permissions.is_empty() {
        return Err(AppError::validation(
            "permissions must contain at least one scope",
        ));
    }

    for scope in permissions {
        let (resource, action) = scope.split_once(':').ok_or_else(|| {
            AppError::validation(format!(
                "malformed scope `{scope}`: expected `resource:action`"
            ))
        })?;

        if resource != WILDCARD && !RESOURCES.contains(&resource) {
            return Err(AppError::validation(format!(
                "unknown resource `{resource}` in scope `{scope}`; valid resources are {} or `*`",
                RESOURCES.join(", ")
            )));
        }
        if action != WILDCARD && !ACTIONS.contains(&action) {
            return Err(AppError::validation(format!(
                "unknown action `{action}` in scope `{scope}`; valid actions are {} or `*`",
                ACTIONS.join(", ")
            )));
        }
    }

    Ok(())
}

/// Expand a scope string into the concrete `(resource, action)` pairs it
/// grants. `invoice:*` becomes all four invoice pairs; `*:read` becomes one
/// per resource.
fn expand(scope: &str) -> Vec<(&'static str, &'static str)> {
    let Some((resource, action)) = scope.split_once(':') else {
        return Vec::new();
    };

    let resources: Vec<&'static str> = if resource == WILDCARD {
        RESOURCES.to_vec()
    } else {
        RESOURCES
            .iter()
            .copied()
            .filter(|r| *r == resource)
            .collect()
    };
    let actions: Vec<&'static str> = if action == WILDCARD {
        ACTIONS.to_vec()
    } else {
        ACTIONS.iter().copied().filter(|a| *a == action).collect()
    };

    resources
        .iter()
        .flat_map(|r| actions.iter().map(move |a| (*r, *a)))
        .collect()
}

/// True iff everything `requested` grants is already granted by `held`.
///
/// This is what makes down-scoped token minting safe. A token may name a
/// *subset* of its minting key's permissions, never a superset - so
/// `POST /auth/tokens` can only ever narrow, and a compromised key cannot be
/// laundered into a broader credential by minting.
///
/// The check works by expansion rather than by string comparison, because
/// string comparison gets wildcards wrong in both directions: a key holding
/// `["invoice:create", "invoice:update", "invoice:delete"]` genuinely can
/// grant `invoice:*`, and a key holding `["invoice:read"]` genuinely cannot,
/// even though neither list contains the literal string.
pub fn is_subset_of(requested: &[String], held: &[String]) -> Result<(), String> {
    for scope in requested {
        let pairs = expand(scope);
        if pairs.is_empty() {
            return Err(scope.clone());
        }
        for (resource, action) in pairs {
            if !has_scope(held, resource, action) {
                return Err(format!("{resource}:{action}"));
            }
        }
    }
    Ok(())
}

/// What a credential must carry to pass a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Any live credential. Used only by the token-mint endpoint, whose whole
    /// job is to trade a credential for a narrower one.
    AnyCredential,
    Scope {
        resource: &'static str,
        action: &'static str,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct RouteScope {
    pub method: &'static str,
    /// axum's matched-path form, e.g. `/invoices/{id}/pay`.
    pub path: &'static str,
    pub access: Access,
    /// Requires a short-lived critical-tier token; a long-lived API key is
    /// rejected with 403 `jwt_required` even if it holds the scope.
    pub critical: bool,
    /// Rejects a JWT. Only the mint endpoint sets this, so that minting can
    /// never be used to extend a token's own life indefinitely.
    pub api_key_only: bool,
}

const fn scope(
    method: &'static str,
    path: &'static str,
    resource: &'static str,
    action: &'static str,
) -> RouteScope {
    RouteScope {
        method,
        path,
        access: Access::Scope { resource, action },
        critical: false,
        api_key_only: false,
    }
}

const fn critical(mut route: RouteScope) -> RouteScope {
    route.critical = true;
    route
}

/// The authorisation requirement for every authenticated route, in one table.
///
/// This is not documentation that sits next to the enforcement - it *is* the
/// enforcement. `auth::middleware` looks the matched route up here and denies
/// before the handler runs, so no handler contains an authorisation `if`, and
/// a route that is missing from this table fails closed (see
/// [`lookup`]'s `None` handling in the middleware). The same table is what
/// `openapi.yaml`'s security section is written from.
pub const ROUTE_SCOPES: &[RouteScope] = &[
    // Trades a key for a 15-minute token carrying a subset of its scopes.
    // Needs no scope of its own - it can only ever narrow.
    RouteScope {
        method: "POST",
        path: "/auth/tokens",
        access: Access::AnyCredential,
        critical: false,
        api_key_only: true,
    },
    // Credential management: the highest-privilege surface in the service.
    // Minting and revoking are separate scopes so that a provisioning job need
    // not also be able to revoke, and an incident-response credential need not
    // also be able to mint. Revocation is a soft delete in the database
    // (`revoked_at = now()`), but the scope names the operation, not the SQL
    // verb it is spelled with.
    critical(scope("POST", "/api_keys", API_KEY, CREATE)),
    critical(scope("DELETE", "/api_keys/{id}", API_KEY, DELETE)),
    scope("GET", "/api_keys", API_KEY, READ),
    // Registering an endpoint mints a signing secret, so it is critical too.
    critical(scope("POST", "/webhook_endpoints", WEBHOOK, CREATE)),
    critical(scope("DELETE", "/webhook_endpoints/{id}", WEBHOOK, DELETE)),
    scope("GET", "/webhook_endpoints", WEBHOOK, READ),
    scope("GET", "/webhook_deliveries", WEBHOOK, READ),
    scope("POST", "/customers", CUSTOMER, CREATE),
    scope("GET", "/customers", CUSTOMER, READ),
    scope("GET", "/customers/{id}", CUSTOMER, READ),
    scope("POST", "/invoices", INVOICE, CREATE),
    scope("GET", "/invoices", INVOICE, READ),
    scope("GET", "/invoices/{id}", INVOICE, READ),
    // Sending and voiding move an existing invoice between states, so they are
    // invoice:update - a key that may author drafts is not thereby a key that
    // may void an issued invoice.
    scope("POST", "/invoices/{id}/send", INVOICE, UPDATE),
    scope("POST", "/invoices/{id}/void", INVOICE, UPDATE),
    // Note this is payment:create, not invoice:*. That separation is the
    // reason the collector key in the seed data can charge an invoice but not
    // edit one. Charging is a *create* because the row it brings into
    // existence is the payment attempt; the invoice write that follows is the
    // same operation completing, and rls.sql's invoices UPDATE policy accepts
    // payment:create for exactly that reason.
    scope("POST", "/invoices/{id}/pay", PAYMENT, CREATE),
];

pub fn lookup(method: &str, matched_path: &str) -> Option<&'static RouteScope> {
    ROUTE_SCOPES
        .iter()
        .find(|r| r.method == method && r.path == matched_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perms(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exact_scope_grants_only_itself() {
        let p = perms(&["invoice:read"]);
        assert!(has_scope(&p, INVOICE, READ));
        for a in MUTATING_ACTIONS {
            assert!(!has_scope(&p, INVOICE, a), "{a}");
        }
        assert!(!has_scope(&p, CUSTOMER, READ));
    }

    #[test]
    fn the_mutating_actions_do_not_imply_each_other() {
        // This is the distinction the four-action grammar exists to make, so
        // assert it across the whole set rather than on one example: holding
        // one mutating action must grant no other mutating action.
        for held in MUTATING_ACTIONS {
            let p = perms(&[&format!("{INVOICE}:{held}")]);
            for other in MUTATING_ACTIONS {
                assert_eq!(
                    has_scope(&p, INVOICE, other),
                    held == other,
                    "invoice:{held} should not decide invoice:{other}"
                );
            }
        }

        // The case with teeth: creating credentials must not confer revoking
        // them, nor the reverse.
        assert!(!has_scope(&perms(&["api_key:create"]), API_KEY, DELETE));
        assert!(!has_scope(&perms(&["api_key:delete"]), API_KEY, CREATE));
    }

    #[test]
    fn every_mutating_action_implies_read_on_the_same_resource_only() {
        for a in MUTATING_ACTIONS {
            let writer = perms(&[&format!("{INVOICE}:{a}")]);
            assert!(has_scope(&writer, INVOICE, a));
            // Implied: otherwise this credential could change an invoice but
            // not be handed it back. See the doc comment on has_scope.
            assert!(has_scope(&writer, INVOICE, READ), "{a}");
            // Not implied anywhere else.
            assert!(!has_scope(&writer, CUSTOMER, READ), "{a}");
            assert!(!has_scope(&writer, PAYMENT, READ), "{a}");
        }

        // The direction that carries the security value is untouched.
        let reader = perms(&["*:read"]);
        for r in RESOURCES {
            assert!(has_scope(&reader, r, READ));
            for a in MUTATING_ACTIONS {
                assert!(!has_scope(&reader, r, a), "{r}:{a}");
            }
        }
    }

    #[test]
    fn wildcards_work_on_both_sides() {
        for a in ACTIONS {
            assert!(has_scope(&perms(&["invoice:*"]), INVOICE, a), "{a}");
        }
        assert!(!has_scope(&perms(&["invoice:*"]), CUSTOMER, READ));

        assert!(has_scope(&perms(&["*:read"]), CUSTOMER, READ));
        assert!(has_scope(&perms(&["*:read"]), API_KEY, READ));
        assert!(!has_scope(&perms(&["*:read"]), CUSTOMER, CREATE));

        // A wildcard resource with a mutating action reads everything too, by
        // the mutating-implies-read rule, but still writes only that action.
        assert!(has_scope(&perms(&["*:update"]), CUSTOMER, READ));
        assert!(!has_scope(&perms(&["*:update"]), CUSTOMER, DELETE));

        let all = perms(&["*:*"]);
        for r in RESOURCES {
            for a in ACTIONS {
                assert!(has_scope(&all, r, a));
            }
        }
    }

    #[test]
    fn grants_are_additive() {
        let collector = perms(&["invoice:read", "payment:create"]);
        assert!(has_scope(&collector, INVOICE, READ));
        assert!(has_scope(&collector, PAYMENT, CREATE));
        assert!(has_scope(&collector, PAYMENT, READ));
        // The things the collector key exists to prove it cannot do. Voiding
        // an invoice is invoice:update, which it does not hold - and which
        // holding invoice:read does not give it.
        assert!(!has_scope(&collector, INVOICE, CREATE));
        assert!(!has_scope(&collector, INVOICE, UPDATE));
        assert!(!has_scope(&collector, INVOICE, DELETE));
        assert!(!has_scope(&collector, PAYMENT, UPDATE));
        assert!(!has_scope(&collector, CUSTOMER, CREATE));
        assert!(!has_scope(&collector, CUSTOMER, READ));
    }

    #[test]
    fn empty_grants_nothing() {
        for r in RESOURCES {
            for a in ACTIONS {
                assert!(!has_scope(&[], r, a));
            }
        }
    }

    #[test]
    fn validation_catches_the_mistakes_people_actually_make() {
        assert!(validate_permissions(&perms(&["invoice:read", "*:*"])).is_ok());
        assert!(validate_permissions(&[]).is_err());
        assert!(validate_permissions(&perms(&["api_key:delete", "invoice:update"])).is_ok());
        // Plural resource - the classic.
        assert!(validate_permissions(&perms(&["invoices:read"])).is_err());
        // `write` is not an action. It was, once; rejecting it rather than
        // quietly treating it as create-or-update is the point - a key asking
        // for it is a key whose author has not yet decided what it may do.
        assert!(validate_permissions(&perms(&["invoice:write"])).is_err());
        assert!(validate_permissions(&perms(&["*:write"])).is_err());
        assert!(validate_permissions(&perms(&["invoice"])).is_err());
        assert!(validate_permissions(&perms(&["*"])).is_err());
    }

    #[test]
    fn every_route_scope_is_a_valid_scope_string() {
        // Stops a typo in the route table from creating a requirement no key
        // could ever be granted.
        for route in ROUTE_SCOPES {
            if let Access::Scope { resource, action } = route.access {
                validate_permissions(&perms(&[&format!("{resource}:{action}")]))
                    .unwrap_or_else(|e| panic!("{} {}: {e}", route.method, route.path));
            }
        }
    }

    #[test]
    fn route_table_has_no_duplicate_entries() {
        // Two entries for one route would mean the effective requirement
        // depends on table order, which is exactly the kind of thing that
        // silently loosens over time.
        for (i, a) in ROUTE_SCOPES.iter().enumerate() {
            for b in &ROUTE_SCOPES[i + 1..] {
                assert!(
                    !(a.method == b.method && a.path == b.path),
                    "duplicate route entry for {} {}",
                    a.method,
                    a.path
                );
            }
        }
    }

    #[test]
    fn minting_can_narrow_but_never_widen() {
        let full = perms(&["*:*"]);
        assert!(is_subset_of(&perms(&["invoice:read"]), &full).is_ok());
        assert!(is_subset_of(&perms(&["*:*"]), &full).is_ok());

        let collector = perms(&["invoice:read", "payment:create"]);
        assert!(is_subset_of(&perms(&["invoice:read"]), &collector).is_ok());
        assert!(is_subset_of(&perms(&["payment:create"]), &collector).is_ok());
        assert!(is_subset_of(&perms(&["payment:read"]), &collector).is_ok());
        // The escalation attempt this exists to stop.
        assert_eq!(
            is_subset_of(&perms(&["invoice:update"]), &collector).unwrap_err(),
            "invoice:update"
        );
        // Widening *within* a resource it already writes is refused too - the
        // finer grammar means this is now a distinct escalation to block.
        assert_eq!(
            is_subset_of(&perms(&["payment:update"]), &collector).unwrap_err(),
            "payment:update"
        );
        assert!(is_subset_of(&perms(&["*:*"]), &collector).is_err());
        assert!(is_subset_of(&perms(&["*:read"]), &collector).is_err());
    }

    #[test]
    fn a_wildcard_can_be_minted_only_if_every_pair_it_covers_is_held() {
        // Holding every mutating action genuinely is holding the wildcard,
        // even though the literal string never appears in the list - read
        // comes along by implication.
        let every = perms(&["invoice:create", "invoice:update", "invoice:delete"]);
        assert!(is_subset_of(&perms(&["invoice:*"]), &every).is_ok());

        // Any one missing and it is not the wildcard. Under the old two-action
        // grammar `invoice:write` alone covered `invoice:*`; now it takes all
        // three, which is the whole point.
        for dropped in MUTATING_ACTIONS {
            let held: Vec<String> = MUTATING_ACTIONS
                .iter()
                .filter(|a| **a != dropped)
                .map(|a| format!("{INVOICE}:{a}"))
                .collect();
            assert!(
                is_subset_of(&perms(&["invoice:*"]), &held).is_err(),
                "invoice:* should not be mintable without invoice:{dropped}"
            );
        }

        assert!(is_subset_of(&perms(&["invoice:*"]), &perms(&["invoice:read"])).is_err());

        // `*:read` needs read on every resource, not just some.
        let partial_read = perms(&["invoice:read", "customer:read"]);
        assert!(is_subset_of(&perms(&["*:read"]), &partial_read).is_err());
    }

    #[test]
    fn credential_management_routes_are_all_critical() {
        // The blast-radius argument in DESIGN.md depends on this being true of
        // every secret-minting route, so assert it rather than trusting the
        // table to have been filled in carefully.
        for route in ROUTE_SCOPES {
            let mints_a_secret = matches!(
                (route.method, route.path),
                ("POST", "/api_keys") | ("POST", "/webhook_endpoints")
            );
            if mints_a_secret {
                assert!(
                    route.critical,
                    "{} {} must be critical",
                    route.method, route.path
                );
            }
        }
    }
}
