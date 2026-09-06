//! Authentication and authorisation.
//!
//! Two tiers of credential, one authorisation path.
//!
//! - Tier 1 - API keys (via `Authorization: Bearer sk_test_...`). Long-lived,
//!   held by machines, carry a permission list. Everything routine uses these.
//!
//! - Tier 2 - short-lived JWTs (`POST /auth/tokens`, 15 minutes). Required
//!   by the handful of routes that mint secrets: creating or revoking API
//!   keys, registering a webhook endpoint.
//!
//! The second tier exists for one reason. Without it, a leaked `*:*` API key
//! lets an attacker mint further credentials at leisure, and revoking the
//! original does nothing about the ones it created. With it, secret creation
//! requires a deliberate, separately-logged, 15-minute token, and the leaked
//! key alone is a dead end. The blast radius of any single credential is one
//! tenant (RLS), the scopes it names, and - for the dangerous routes - a
//! window you can watch.
//!
//! Both tiers converge on one claims document, which becomes the
//! `request.jwt.claims` GUC that the RLS policies read. See [`jwt`] for why
//! the JWT path passes those bytes through untouched.

pub mod api_key;
pub mod jwt;
pub mod middleware;
pub mod permissions;

use serde_json::json;
use uuid::Uuid;

/// Who is calling, resolved once by the middleware and read by handlers.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub business_id: Uuid,
    pub permissions: Vec<String>,
    pub tier: String,
    /// The exact JSON the database will see for this request.
    pub raw_claims: String,
    /// Set for API-key requests, so `last_used_at` can be touched and so logs
    /// can name the credential without ever naming its secret.
    pub api_key_id: Option<Uuid>,
    pub api_key_prefix: Option<String>,
}

impl AuthContext {
    /// Build the claims document for an API-key request.
    pub fn from_api_key(
        business_id: Uuid,
        permissions: Vec<String>,
        api_key_id: Uuid,
        api_key_prefix: String,
    ) -> Self {
        let raw_claims = json!({
            "sub": business_id.to_string(),
            "role": "invoice_app",
            "claims": {
                "business_id": business_id.to_string(),
                "permissions": permissions,
                "tier": jwt::TIER_STANDARD,
            }
        })
        .to_string();

        Self {
            business_id,
            permissions,
            tier: jwt::TIER_STANDARD.to_string(),
            raw_claims,
            api_key_id: Some(api_key_id),
            api_key_prefix: Some(api_key_prefix),
        }
    }

    pub fn from_token(verified: jwt::VerifiedToken) -> Self {
        Self {
            business_id: verified.business_id,
            permissions: verified.permissions,
            tier: verified.tier,
            raw_claims: verified.raw_claims,
            api_key_id: None,
            api_key_prefix: None,
        }
    }

    pub fn has_scope(&self, resource: &str, action: &str) -> bool {
        permissions::has_scope(&self.permissions, resource, action)
    }

    pub fn is_critical_tier(&self) -> bool {
        self.tier == jwt::TIER_CRITICAL
    }
}
