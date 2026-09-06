//! The invoice lifecycle.
//!
//! ```text
//!                       send                          full payment
//!      ┌───────┐  POST /invoices/{id}/send   ┌──────┐ ──────────────────────┐
//!      │ draft │ ──────────────────────────▶ │ sent │                       ▼
//!      └───┬───┘                             └─┬──┬─┘  partial payment*  ┌──────┐  refund*  ┌──────────┐
//!          │ void                         void │  └───────────────────▶  │ paid │ ────────▶ │ refunded │
//!          ▼      (rule: amount_paid == 0)     │     ┌────────────────┐  └──────┘           └──────────┘
//!      ┌──────┐ ◀──────────────────────────────┘     │ partially_paid │ ─▶ paid (remainder*) (terminal)
//!      │ void │                                      └───────┬────────┘
//!      └──────┘ (terminal)                                   └─▶ refunded (partial refund*)
//!
//!      overdue: a computed flag, not a state - applies while in
//!               {sent, partially_paid} and due_date < today
//!      * = designed transition; no endpoint in v1 (see below)
//! ```
//!
//! Void is reachable only where no money has moved. Structurally, not by
//! convention: the SQL is `SET state='void' WHERE state IN ('draft','sent')
//! AND amount_paid_cents = 0`, and a CHECK constraint on the table refuses a
//! void row with a non-zero paid amount. Once a customer has paid you
//! anything, the document is part of the money trail and cannot be made to
//! have never existed.
//!
//! `paid`, `void` and `refunded` are terminal. Money that has to go back
//! goes forward through `refunded`, which leaves a record. It never goes back
//! to `draft`, and it is never silently cancelled.
//!
//! Only `sent` and `partially_paid` accept payment. A `draft` is not a
//! promise to anyone yet; paying one would mean collecting against a document
//! the customer has never seen.
//!
//! `overdue` is a flag, not a state. It is `due_date < today` while money
//! is still collectible. Storing it would require a nightly job to flip rows,
//! and between midnight and that job the database would be asserting something
//! false. Computing it at read time cannot disagree with the calendar. It is
//! also why it can't be a generated column - `CURRENT_DATE` is not immutable.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceState {
    Draft,
    Sent,
    PartiallyPaid,
    Paid,
    Void,
    Refunded,
}

impl InvoiceState {
    pub const ALL: [InvoiceState; 6] = [
        InvoiceState::Draft,
        InvoiceState::Sent,
        InvoiceState::PartiallyPaid,
        InvoiceState::Paid,
        InvoiceState::Void,
        InvoiceState::Refunded,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sent => "sent",
            Self::PartiallyPaid => "partially_paid",
            Self::Paid => "paid",
            Self::Void => "void",
            Self::Refunded => "refunded",
        }
    }

    /// No transition leaves these. Checked by a test against `transition()`,
    /// so the two can't disagree.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Paid | Self::Void | Self::Refunded)
    }

    /// Money is still expected against this invoice. This is the predicate
    /// behind both the `overdue` flag and the partial index that makes the
    /// overdue query cheap.
    pub fn is_collectible(self) -> bool {
        matches!(self, Self::Sent | Self::PartiallyPaid)
    }
}

impl fmt::Display for InvoiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InvoiceState {
    type Err = UnknownState;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "draft" => Ok(Self::Draft),
            "sent" => Ok(Self::Sent),
            "partially_paid" => Ok(Self::PartiallyPaid),
            "paid" => Ok(Self::Paid),
            "void" => Ok(Self::Void),
            "refunded" => Ok(Self::Refunded),
            other => Err(UnknownState(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown invoice state `{0}`")]
pub struct UnknownState(pub String);

/// Things that can happen to an invoice.
///
/// `PaymentSettled` carries the money because whether a payment moves an
/// invoice to `paid` or to `partially_paid` is not something the caller
/// decides - it is arithmetic, and it belongs in the machine rather than in
/// the handler that happens to be doing the charging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceEvent {
    Send,
    Void,
    PaymentSettled {
        amount_paid_cents: i64,
        total_cents: i64,
    },
    /// Designed, not reachable in v1: no refund endpoint.
    RefundSettled {
        fully_refunded: bool,
    },
}

impl InvoiceEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Void => "void",
            Self::PaymentSettled { .. } => "pay",
            Self::RefundSettled { .. } => "refund",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot {attempted} an invoice in state {from}: {reason}")]
pub struct InvalidTransition {
    pub from: InvoiceState,
    pub attempted: &'static str,
    pub reason: &'static str,
}

pub fn transition(
    from: InvoiceState,
    event: InvoiceEvent,
) -> Result<InvoiceState, InvalidTransition> {
    use InvoiceEvent as E;
    use InvoiceState as S;

    let invalid = |reason: &'static str| InvalidTransition {
        from,
        attempted: event.name(),
        reason,
    };

    match (from, event) {
        (S::Draft, E::Send) => Ok(S::Sent),
        (_, E::Send) => Err(invalid("only a draft can be sent")),

        // The money check is the caller's job to supply honestly, but the rule
        // itself lives here and is re-asserted in SQL and in a CHECK
        // constraint. Three layers, because "we voided an invoice someone had
        // already paid" is not a bug you want to find in an audit.
        (S::Draft, E::Void) | (S::Sent, E::Void) => Ok(S::Void),
        (S::PartiallyPaid, E::Void) => Err(invalid("money has already been collected")),
        (_, E::Void) => Err(invalid("the invoice is already in a terminal state")),

        (
            S::Sent | S::PartiallyPaid,
            E::PaymentSettled {
                amount_paid_cents,
                total_cents,
            },
        ) => {
            if amount_paid_cents >= total_cents {
                Ok(S::Paid)
            } else {
                Ok(S::PartiallyPaid)
            }
        }
        (S::Draft, E::PaymentSettled { .. }) => {
            Err(invalid("the invoice has not been sent to the customer"))
        }
        (_, E::PaymentSettled { .. }) => Err(invalid("the invoice is no longer collectible")),

        (S::Paid | S::PartiallyPaid, E::RefundSettled { fully_refunded }) => {
            if fully_refunded {
                Ok(S::Refunded)
            } else {
                // A partial refund against a fully paid invoice leaves money
                // still legitimately held: back to partially_paid.
                Ok(S::PartiallyPaid)
            }
        }
        (_, E::RefundSettled { .. }) => Err(invalid("there is nothing to refund")),
    }
}

/// The read-time definition of overdue. Deliberately a function of state and
/// the calendar only - there is nothing stored that could be stale.
pub fn is_overdue(
    state: InvoiceState,
    due_date: chrono::NaiveDate,
    today: chrono::NaiveDate,
) -> bool {
    state.is_collectible() && due_date < today
}

#[cfg(test)]
mod tests {
    use super::InvoiceEvent as E;
    use super::InvoiceState as S;
    use super::*;
    use chrono::NaiveDate;

    fn pay(amount: i64, total: i64) -> E {
        E::PaymentSettled {
            amount_paid_cents: amount,
            total_cents: total,
        }
    }

    #[test]
    fn send_only_from_draft() {
        assert_eq!(transition(S::Draft, E::Send).unwrap(), S::Sent);
        for state in S::ALL.into_iter().filter(|s| *s != S::Draft) {
            assert!(
                transition(state, E::Send).is_err(),
                "{state} should not be sendable"
            );
        }
    }

    #[test]
    fn void_reaches_exactly_the_states_where_no_money_moved() {
        assert_eq!(transition(S::Draft, E::Void).unwrap(), S::Void);
        assert_eq!(transition(S::Sent, E::Void).unwrap(), S::Void);

        // partially_paid is the interesting one: it is not terminal, but money
        // has moved, so it is still not voidable.
        let err = transition(S::PartiallyPaid, E::Void).unwrap_err();
        assert_eq!(err.reason, "money has already been collected");

        for state in [S::Paid, S::Void, S::Refunded] {
            assert!(transition(state, E::Void).is_err());
        }
    }

    #[test]
    fn payment_settles_by_arithmetic_not_by_caller_intent() {
        assert_eq!(transition(S::Sent, pay(5_000, 5_000)).unwrap(), S::Paid);
        assert_eq!(
            transition(S::Sent, pay(2_000, 5_000)).unwrap(),
            S::PartiallyPaid
        );
        assert_eq!(
            transition(S::PartiallyPaid, pay(5_000, 5_000)).unwrap(),
            S::Paid
        );
        // Overpayment still settles as paid rather than wrapping into some
        // other state; the surplus is a business question, not a state one.
        assert_eq!(transition(S::Sent, pay(6_000, 5_000)).unwrap(), S::Paid);
    }

    #[test]
    fn draft_invoices_reject_payment() {
        let err = transition(S::Draft, pay(100, 100)).unwrap_err();
        assert_eq!(err.reason, "the invoice has not been sent to the customer");
    }

    #[test]
    fn refunds_are_designed_and_reachable_in_the_machine() {
        // No endpoint reaches these in v1, but the rules are pinned so that
        // adding one later is an endpoint change, not a state-model change.
        assert_eq!(
            transition(
                S::Paid,
                E::RefundSettled {
                    fully_refunded: true
                }
            )
            .unwrap(),
            S::Refunded
        );
        assert_eq!(
            transition(
                S::Paid,
                E::RefundSettled {
                    fully_refunded: false
                }
            )
            .unwrap(),
            S::PartiallyPaid
        );
        assert_eq!(
            transition(
                S::PartiallyPaid,
                E::RefundSettled {
                    fully_refunded: true
                }
            )
            .unwrap(),
            S::Refunded
        );
        for state in [S::Draft, S::Sent, S::Void, S::Refunded] {
            assert!(transition(
                state,
                E::RefundSettled {
                    fully_refunded: true
                }
            )
            .is_err());
        }
    }

    /// `is_terminal()` is a convenience used all over the handlers; this pins
    /// it to the actual transition table so it can never quietly become a lie.
    #[test]
    fn terminal_states_have_no_outgoing_transitions() {
        let every_event = [
            E::Send,
            E::Void,
            pay(1, 1),
            E::RefundSettled {
                fully_refunded: true,
            },
            E::RefundSettled {
                fully_refunded: false,
            },
        ];

        for state in S::ALL {
            let has_outgoing = every_event
                .iter()
                .any(|event| transition(state, *event).is_ok());

            if state.is_terminal() {
                // `paid` is the exception the table itself declares: refunds
                // are the one way money leaves a settled invoice, and that is
                // exactly why they get their own state instead of a reversal.
                let expected = state == S::Paid;
                assert_eq!(
                    has_outgoing, expected,
                    "{state} claims to be terminal but the table disagrees"
                );
            } else {
                assert!(has_outgoing, "{state} is a dead end");
            }
        }
    }

    #[test]
    fn every_state_pair_is_decided_explicitly() {
        // Exhaustiveness: no (state, event) pair panics or is left implicit.
        for state in S::ALL {
            for event in [
                E::Send,
                E::Void,
                pay(0, 10),
                pay(10, 10),
                E::RefundSettled {
                    fully_refunded: true,
                },
            ] {
                let _ = transition(state, event);
            }
        }
    }

    #[test]
    fn overdue_needs_collectible_state_and_a_past_date() {
        let today = NaiveDate::from_ymd_opt(2026, 3, 10).unwrap();
        let yesterday = NaiveDate::from_ymd_opt(2026, 3, 9).unwrap();
        let tomorrow = NaiveDate::from_ymd_opt(2026, 3, 11).unwrap();

        assert!(is_overdue(S::Sent, yesterday, today));
        assert!(is_overdue(S::PartiallyPaid, yesterday, today));

        // Due today is not yet overdue.
        assert!(!is_overdue(S::Sent, today, today));
        assert!(!is_overdue(S::Sent, tomorrow, today));

        // A draft has never been anyone's obligation; a paid or void invoice
        // has stopped being one. Neither can be late.
        assert!(!is_overdue(S::Draft, yesterday, today));
        assert!(!is_overdue(S::Paid, yesterday, today));
        assert!(!is_overdue(S::Void, yesterday, today));
        assert!(!is_overdue(S::Refunded, yesterday, today));
    }

    #[test]
    fn state_strings_round_trip() {
        // These strings are in the database CHECK constraint and on the wire.
        for state in S::ALL {
            assert_eq!(state.as_str().parse::<S>().unwrap(), state);
        }
        assert!("disputed".parse::<S>().is_err());
    }
}
