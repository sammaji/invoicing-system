//! Short-lived jwt tokens.
//!
//! The verified token's payload segment is decoded and carried around
//! verbatim as [`VerifiedToken::raw_claims`], and that exact byte string
//! is what gets written into the `request.jwt.claims` GUC that every RLS
//! policy reads. It is never re-serialised from a Rust struct.
//!
//! That matters because re-serialising is where drift comes from: add a field
//! to the struct, forget to add it to the SQL helper, and now the policy is
//! reading something the token doesn't say. Passing the bytes through means
//! the database is looking at precisely the document that was signed.
//!
//! # Claims shape
//!
//! ```json
//! { "sub": "<business_id>", "role": "invoice_app", "iat": .., "exp": ..,
//!   "claims": { "business_id": "..", "permissions": ["api_key:create"],
//!               "tier": "critical" } }
//! ```
//!
//! The nested `claims` object is what SQL reads (`app_business_id()`,
//! `app_permissions()`, `app_tier()`). API-key requests synthesise a document
//! of exactly this shape with `"tier": "standard"`, so there is one format for
//! the policies to understand rather than two.
//!
use base64::Engine;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

pub const TIER_CRITICAL: &str = "critical";
pub const TIER_STANDARD: &str = "standard";

#[derive(Debug, Serialize, Deserialize)]
pub struct InnerClaims {
    pub business_id: Uuid,
    pub permissions: Vec<String>,
    pub tier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
    pub claims: InnerClaims,
}

pub struct VerifiedToken {
    pub business_id: Uuid,
    pub permissions: Vec<String>,
    pub tier: String,
    /// The payload segment as signed. Goes into the GUC unmodified.
    pub raw_claims: String,
}

#[derive(Clone)]
pub struct JwtCodec {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
}

impl JwtCodec {
    pub fn new(secret: &str) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        // Fail closed on algorithm confusion: only HS256 is ever accepted, and
        // `alg: none` is rejected by the library's own algorithm list.
        validation.algorithms = vec![Algorithm::HS256];
        validation.validate_exp = true;
        // These tokens live 15 minutes; a minute of clock skew tolerance is
        // the default and is the right order of magnitude here.
        validation.required_spec_claims = ["exp", "sub"].iter().map(|s| s.to_string()).collect();

        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            validation,
        }
    }

    pub fn mint(
        &self,
        business_id: Uuid,
        permissions: Vec<String>,
        ttl: std::time::Duration,
    ) -> AppResult<(String, i64)> {
        let now = chrono::Utc::now().timestamp();
        let exp = now + ttl.as_secs() as i64;

        let claims = TokenClaims {
            sub: business_id.to_string(),
            role: "invoice_app".to_string(),
            iat: now,
            exp,
            claims: InnerClaims {
                business_id,
                permissions,
                tier: TIER_CRITICAL.to_string(),
            },
        };

        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("failed to mint token: {e}")))?;

        Ok((token, exp))
    }

    pub fn verify(&self, token: &str) -> AppResult<VerifiedToken> {
        let data = decode::<TokenClaims>(token, &self.decoding, &self.validation).map_err(|e| {
            tracing::debug!(error = %e, "token verification failed");
            AppError::Unauthorized("invalid or expired token".to_string())
        })?;

        let raw_claims = raw_payload(token)?;

        Ok(VerifiedToken {
            business_id: data.claims.claims.business_id,
            permissions: data.claims.claims.permissions,
            tier: data.claims.claims.tier,
            raw_claims,
        })
    }
}

fn raw_payload(token: &str) -> AppResult<String> {
    let payload_segment = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AppError::Unauthorized("malformed token".to_string()))?;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(|_| AppError::Unauthorized("malformed token".to_string()))?;

    String::from_utf8(bytes).map_err(|_| AppError::Unauthorized("malformed token".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn codec() -> JwtCodec {
        JwtCodec::new("test-secret")
    }

    #[test]
    fn mints_and_verifies() {
        let business_id = Uuid::now_v7();
        let (token, exp) = codec()
            .mint(
                business_id,
                vec!["api_key:create".to_string()],
                Duration::from_secs(900),
            )
            .unwrap();

        assert!(exp > chrono::Utc::now().timestamp());

        let verified = codec().verify(&token).unwrap();
        assert_eq!(verified.business_id, business_id);
        assert_eq!(verified.permissions, vec!["api_key:create".to_string()]);
        assert_eq!(verified.tier, TIER_CRITICAL);
    }

    #[test]
    fn raw_claims_are_the_signed_bytes_and_parse_as_the_guc_shape() {
        let business_id = Uuid::now_v7();
        let (token, _) = codec()
            .mint(
                business_id,
                vec!["invoice:read".into()],
                Duration::from_secs(900),
            )
            .unwrap();
        let verified = codec().verify(&token).unwrap();

        // What the database will see.
        let parsed: serde_json::Value = serde_json::from_str(&verified.raw_claims).unwrap();
        assert_eq!(
            parsed["claims"]["business_id"].as_str().unwrap(),
            business_id.to_string()
        );
        assert_eq!(parsed["claims"]["tier"].as_str().unwrap(), TIER_CRITICAL);
        assert_eq!(
            parsed["claims"]["permissions"][0].as_str().unwrap(),
            "invoice:read"
        );

        // And it really is the token's own payload segment, not a re-encode.
        let segment = token.split('.').nth(1).unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .unwrap();
        assert_eq!(verified.raw_claims.as_bytes(), decoded.as_slice());
    }

    #[test]
    fn rejects_a_token_signed_with_another_secret() {
        let (token, _) = JwtCodec::new("attacker-secret")
            .mint(Uuid::now_v7(), vec!["*:*".into()], Duration::from_secs(900))
            .unwrap();
        assert!(codec().verify(&token).is_err());
    }

    #[test]
    fn rejects_expired_tokens() {
        let (token, _) = codec()
            .mint(Uuid::now_v7(), vec!["*:*".into()], Duration::from_secs(0))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        // jsonwebtoken allows 60s leeway by default, so an exp of "now" is
        // still inside the window. Assert on a definitively stale token
        // instead by minting one in the past.
        let now = chrono::Utc::now().timestamp();
        let stale = TokenClaims {
            sub: Uuid::now_v7().to_string(),
            role: "invoice_app".into(),
            iat: now - 7200,
            exp: now - 3600,
            claims: InnerClaims {
                business_id: Uuid::now_v7(),
                permissions: vec!["*:*".into()],
                tier: TIER_CRITICAL.into(),
            },
        };
        let stale_token = encode(
            &Header::new(Algorithm::HS256),
            &stale,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap();

        assert!(codec().verify(&stale_token).is_err());
        // The fresh one is still fine.
        assert!(codec().verify(&token).is_ok());
    }

    #[test]
    fn rejects_garbage() {
        assert!(codec().verify("").is_err());
        assert!(codec().verify("not.a.token").is_err());
        assert!(codec()
            .verify("sk_test_demofull000000000000000000000001")
            .is_err());
    }
}
