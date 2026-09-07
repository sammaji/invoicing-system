use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::domain::ids;
use crate::domain::state_machine::{is_overdue, InvoiceState};

/* -------------------------------------------------------------------------- */
/* customers                                                                  */
/* -------------------------------------------------------------------------- */

#[derive(Debug, FromRow)]
pub struct CustomerRow {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct CustomerResponse {
    pub id: String,
    pub object: &'static str,
    pub name: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl From<CustomerRow> for CustomerResponse {
    fn from(row: CustomerRow) -> Self {
        Self {
            id: ids::format_id(ids::CUSTOMER, row.id),
            object: "customer",
            name: row.name,
            email: row.email,
            created_at: row.created_at,
        }
    }
}

/* -------------------------------------------------------------------------- */
/* invoices                                                                   */
/* -------------------------------------------------------------------------- */

#[derive(Debug, FromRow)]
pub struct InvoiceRow {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub state: String,
    pub total_cents: i64,
    pub amount_paid_cents: i64,
    pub currency: String,
    pub due_date: NaiveDate,
    pub sent_at: Option<DateTime<Utc>>,
    pub paid_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl InvoiceRow {
    pub fn state(&self) -> InvoiceState {
        self.state.parse().unwrap_or_else(|_| {
            panic!(
                "invoice {} has state `{}`, which this build does not know about",
                self.id, self.state
            )
        })
    }

    pub fn amount_remaining_cents(&self) -> i64 {
        crate::domain::money::remaining(self.total_cents, self.amount_paid_cents)
    }
}

#[derive(Debug, FromRow)]
pub struct LineItemRow {
    pub id: Uuid,
    pub description: String,
    pub quantity: i32,
    pub unit_amount_cents: i64,
    pub amount_cents: i64,
}

#[derive(Debug, Serialize)]
pub struct LineItemResponse {
    pub id: String,
    pub description: String,
    pub quantity: i32,
    pub unit_amount_cents: i64,
    pub amount_cents: i64,
}

impl From<LineItemRow> for LineItemResponse {
    fn from(row: LineItemRow) -> Self {
        Self {
            id: ids::format_id(ids::LINE_ITEM, row.id),
            description: row.description,
            quantity: row.quantity,
            unit_amount_cents: row.unit_amount_cents,
            amount_cents: row.amount_cents,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InvoiceResponse {
    pub id: String,
    pub object: &'static str,
    pub customer_id: String,
    pub state: InvoiceState,
    pub overdue: bool,
    pub total_cents: i64,
    pub amount_paid_cents: i64,
    pub amount_remaining_cents: i64,
    pub currency: String,
    pub due_date: NaiveDate,
    pub sent_at: Option<DateTime<Utc>>,
    pub paid_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_items: Option<Vec<LineItemResponse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_attempts: Option<Vec<PaymentAttemptResponse>>,
}

impl InvoiceResponse {
    pub fn new(row: InvoiceRow) -> Self {
        let state = row.state();
        let today = Utc::now().date_naive();

        Self {
            id: ids::format_id(ids::INVOICE, row.id),
            object: "invoice",
            customer_id: ids::format_id(ids::CUSTOMER, row.customer_id),
            state,
            overdue: is_overdue(state, row.due_date, today),
            total_cents: row.total_cents,
            amount_paid_cents: row.amount_paid_cents,
            amount_remaining_cents: row.amount_remaining_cents(),
            currency: row.currency,
            due_date: row.due_date,
            sent_at: row.sent_at,
            paid_at: row.paid_at,
            created_at: row.created_at,
            line_items: None,
            payment_attempts: None,
        }
    }

    pub fn with_line_items(mut self, items: Vec<LineItemRow>) -> Self {
        self.line_items = Some(items.into_iter().map(Into::into).collect());
        self
    }

    pub fn with_payment_attempts(mut self, attempts: Vec<PaymentAttemptRow>) -> Self {
        self.payment_attempts = Some(attempts.into_iter().map(Into::into).collect());
        self
    }
}

/* -------------------------------------------------------------------------- */
/* payment attempts                                                           */
/* -------------------------------------------------------------------------- */

#[derive(Debug, FromRow)]
pub struct PaymentAttemptRow {
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub status: String,
    pub processor: String,
    pub amount_cents: i64,
    pub psp_ref: Option<String>,
    pub failure_code: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct PaymentAttemptResponse {
    pub id: String,
    pub object: &'static str,
    pub invoice_id: String,
    pub status: String,
    /// Which provider handled it. Surfaced because when something goes wrong
    /// the first question anyone asks is "which processor was this?".
    pub processor: String,
    pub amount_cents: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psp_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<PaymentAttemptRow> for PaymentAttemptResponse {
    fn from(row: PaymentAttemptRow) -> Self {
        Self {
            id: ids::format_id(ids::PAYMENT_ATTEMPT, row.id),
            object: "payment_attempt",
            invoice_id: ids::format_id(ids::INVOICE, row.invoice_id),
            status: row.status,
            processor: row.processor,
            amount_cents: row.amount_cents,
            psp_ref: row.psp_ref,
            failure_code: row.failure_code,
            created_at: row.created_at,
        }
    }
}

/* -------------------------------------------------------------------------- */
/* api keys                                                                   */
/* -------------------------------------------------------------------------- */

#[derive(Debug, FromRow)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub object: &'static str,
    pub name: String,
    /// The first eight characters, so a key can be identified in a dashboard
    /// or a log line without the secret ever being recoverable.
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl From<ApiKeyRow> for ApiKeyResponse {
    fn from(row: ApiKeyRow) -> Self {
        Self {
            id: ids::format_id(ids::API_KEY, row.id),
            object: "api_key",
            name: row.name,
            key_prefix: row.key_prefix,
            permissions: row.permissions,
            revoked_at: row.revoked_at,
            last_used_at: row.last_used_at,
            created_at: row.created_at,
            key: None,
        }
    }
}

/* -------------------------------------------------------------------------- */
/* webhooks                                                                   */
/* -------------------------------------------------------------------------- */

#[derive(Debug, FromRow)]
pub struct WebhookEndpointRow {
    pub id: Uuid,
    pub url: String,
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WebhookEndpointResponse {
    pub id: String,
    pub object: &'static str,
    pub url: String,
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Returned once, at registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl From<WebhookEndpointRow> for WebhookEndpointResponse {
    fn from(row: WebhookEndpointRow) -> Self {
        Self {
            id: ids::format_id(ids::WEBHOOK_ENDPOINT, row.id),
            object: "webhook_endpoint",
            url: row.url,
            disabled_at: row.disabled_at,
            created_at: row.created_at,
            secret: None,
        }
    }
}

#[derive(Debug, FromRow)]
pub struct WebhookDeliveryRow {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub event_id: Uuid,
    pub event_type: String,
    pub status: String,
    pub attempt_count: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WebhookDeliveryResponse {
    pub id: String,
    pub object: &'static str,
    pub endpoint_id: String,
    pub event_id: String,
    pub event_type: String,
    pub status: String,
    pub attempt_count: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<WebhookDeliveryRow> for WebhookDeliveryResponse {
    fn from(row: WebhookDeliveryRow) -> Self {
        Self {
            id: ids::format_id(ids::WEBHOOK_DELIVERY, row.id),
            object: "webhook_delivery",
            endpoint_id: ids::format_id(ids::WEBHOOK_ENDPOINT, row.endpoint_id),
            event_id: ids::format_id(ids::EVENT, row.event_id),
            event_type: row.event_type,
            status: row.status,
            attempt_count: row.attempt_count,
            next_attempt_at: row.next_attempt_at,
            last_error: row.last_error,
            delivered_at: row.delivered_at,
            created_at: row.created_at,
        }
    }
}

/* -------------------------------------------------------------------------- */
/* list envelopes                                                             */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Serialize)]
pub struct ListResponse<T> {
    pub object: &'static str,
    pub data: Vec<T>,
    pub has_more: bool,
}

impl<T> ListResponse<T> {
    pub fn new(data: Vec<T>, has_more: bool) -> Self {
        Self {
            object: "list",
            data,
            has_more,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Pagination {
    /// Deserialized via a string-tolerant helper because this struct is
    /// `#[serde(flatten)]`ed into other query structs, and serde's flatten
    /// buffers every query value as a string - a plain `Option<i64>` would
    /// reject `?limit=25` with a 400 on exactly those routes.
    #[serde(default, deserialize_with = "de_opt_i64")]
    pub limit: Option<i64>,
    /// The id of the last item on the previous page.
    #[serde(default)]
    pub starting_after: Option<String>,
}

fn de_opt_i64<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum IntOrString {
        Int(i64),
        String(String),
    }

    match Option::<IntOrString>::deserialize(deserializer)? {
        None => Ok(None),
        Some(IntOrString::Int(n)) => Ok(Some(n)),
        Some(IntOrString::String(s)) => s
            .parse::<i64>()
            .map(Some)
            .map_err(|_| serde::de::Error::custom("limit must be an integer")),
    }
}

impl Pagination {
    pub const DEFAULT_LIMIT: i64 = 25;
    pub const MAX_LIMIT: i64 = 100;

    pub fn limit(&self) -> i64 {
        self.limit
            .unwrap_or(Self::DEFAULT_LIMIT)
            .clamp(1, Self::MAX_LIMIT)
    }
}
