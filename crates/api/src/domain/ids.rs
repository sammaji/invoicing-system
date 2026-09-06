//! Prefixed external identifiers.
//!
//! Internally every row is keyed by a UUIDv7 - sortable, index-friendly, and
//! generated without a round trip. Externally those UUIDs are wrapped in a
//! type prefix (`inv_`, `cus_`, `pa_`...) because an identifier that says what
//! it is turns a whole class of integration bug into an immediate 400: pasting
//! a customer id into an invoice route fails at parse time with a clear
//! message instead of 404-ing somewhere confusing.

use crate::error::{AppError, AppResult};
use uuid::Uuid;

pub const CUSTOMER: &str = "cus";
pub const INVOICE: &str = "inv";
pub const LINE_ITEM: &str = "li";
pub const PAYMENT_ATTEMPT: &str = "pa";
pub const WEBHOOK_ENDPOINT: &str = "whe";
pub const WEBHOOK_DELIVERY: &str = "whd";
pub const API_KEY: &str = "ak";
pub const EVENT: &str = "evt";

/// `inv_0192f0a1b2c34567890abcdef0123456` - the UUID's hex with dashes
/// stripped, so the whole thing double-clicks as one token in a terminal.
pub fn format_id(prefix: &str, id: Uuid) -> String {
    format!("{prefix}_{}", id.simple())
}

pub fn parse_id(prefix: &str, value: &str) -> AppResult<Uuid> {
    let rest = value.strip_prefix(prefix).and_then(|r| r.strip_prefix('_'));

    match rest {
        Some(hex) => Uuid::parse_str(hex).map_err(|_| {
            AppError::validation(format!("malformed identifier: {value}"))
        }),
        None => Err(AppError::validation(format!(
            "expected an identifier starting with `{prefix}_`, got `{value}`"
        ))),
    }
}

pub fn new_id() -> Uuid {
    Uuid::now_v7()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let id = new_id();
        let formatted = format_id(INVOICE, id);
        assert!(formatted.starts_with("inv_"));
        assert!(!formatted.contains('-'));
        assert_eq!(parse_id(INVOICE, &formatted).unwrap(), id);
    }

    #[test]
    fn rejects_the_wrong_resource_type() {
        let id = format_id(CUSTOMER, new_id());
        // The point of the prefix: this is a 400 at the edge, not a 404 later.
        assert!(parse_id(INVOICE, &id).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_id(INVOICE, "inv_nothex").is_err());
        assert!(parse_id(INVOICE, "").is_err());
        assert!(parse_id(INVOICE, "inv_").is_err());
    }
}
