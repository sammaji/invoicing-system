//! Money.
//!
//! Amounts are integer minor units (cents) as `i64`, everywhere, with no
//! exceptions and no floating point anywhere in the path. `i64` cents covers
//! ±92 quadrillion, which is not a limit anyone will meet, but arithmetic is
//! still checked: an overflow that wraps silently is a wrong number on an
//! invoice, and a wrong number on an invoice is worse than a 400.

use crate::error::{AppError, AppResult};

pub const MAX_AMOUNT_CENTS: i64 = 1_000_000_000_000; // 10 billion major units

pub fn line_amount(quantity: i32, unit_amount_cents: i64) -> AppResult<i64> {
    if quantity <= 0 {
        return Err(AppError::validation("quantity must be greater than zero"));
    }
    if unit_amount_cents < 0 {
        return Err(AppError::validation(
            "unit_amount_cents must not be negative",
        ));
    }
    if unit_amount_cents > MAX_AMOUNT_CENTS {
        return Err(AppError::validation(format!(
            "unit_amount_cents must not exceed {MAX_AMOUNT_CENTS}"
        )));
    }

    i64::from(quantity)
        .checked_mul(unit_amount_cents)
        .filter(|total| *total <= MAX_AMOUNT_CENTS)
        .ok_or_else(|| AppError::validation("line item amount is too large"))
}

pub fn sum_amounts(amounts: &[i64]) -> AppResult<i64> {
    let mut total: i64 = 0;
    for amount in amounts {
        total = total
            .checked_add(*amount)
            .filter(|t| *t <= MAX_AMOUNT_CENTS)
            .ok_or_else(|| AppError::validation("invoice total is too large"))?;
    }
    Ok(total)
}

/// What is still owed. Saturating rather than checked because the schema
/// already guarantees `0 <= amount_paid <= total`; if that ever fails we would
/// rather return zero-owed than panic mid-payment.
pub fn remaining(total_cents: i64, amount_paid_cents: i64) -> i64 {
    total_cents.saturating_sub(amount_paid_cents).max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplies_and_sums() {
        assert_eq!(line_amount(3, 1_050).unwrap(), 3_150);
        assert_eq!(sum_amounts(&[3_150, 99, 1]).unwrap(), 3_250);
        assert_eq!(sum_amounts(&[]).unwrap(), 0);
    }

    #[test]
    fn zero_priced_lines_are_legal() {
        // A zero-amount line is a real thing (an included item, a comped
        // extra). Zero quantity is not.
        assert_eq!(line_amount(2, 0).unwrap(), 0);
        assert!(line_amount(0, 100).is_err());
        assert!(line_amount(-1, 100).is_err());
    }

    #[test]
    fn overflow_is_rejected_not_wrapped() {
        assert!(line_amount(i32::MAX, i64::MAX).is_err());
        assert!(line_amount(1, i64::MAX).is_err());
        assert!(sum_amounts(&[MAX_AMOUNT_CENTS, MAX_AMOUNT_CENTS]).is_err());
    }

    #[test]
    fn remaining_never_goes_negative() {
        assert_eq!(remaining(1_000, 400), 600);
        assert_eq!(remaining(1_000, 1_000), 0);
        assert_eq!(remaining(1_000, 1_500), 0);
    }
}
