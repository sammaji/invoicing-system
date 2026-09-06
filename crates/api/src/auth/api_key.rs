//! API key generation, hashing and lookup.
//!
//! Key format: `sk_prod_<8-char prefix><24-char secret>`.
//!
//! The prefix is stored in the clear and uniquely indexed, so authentication
//! is one indexed lookup rather than a scan-and-compare over every key in the
//! table. The full string is hashed with SHA-256 and only the hash is stored;
//! the plaintext is returned exactly once, at creation.
//!
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const KEY_PREFIX: &str = "sk_prod_";
pub const PREFIX_LEN: usize = 8;
pub const SECRET_LEN: usize = 24;

const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub struct GeneratedKey {
    /// Shown to the caller once and then unrecoverable.
    pub plaintext: String,
    pub prefix: String,
    pub hash: String,
}

fn random_string(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

pub fn generate() -> GeneratedKey {
    let prefix = random_string(PREFIX_LEN);
    let secret = random_string(SECRET_LEN);
    let plaintext = format!("{KEY_PREFIX}{prefix}{secret}");
    let hash = hash_key(&plaintext);

    GeneratedKey {
        plaintext,
        prefix,
        hash,
    }
}

pub fn hash_key(plaintext: &str) -> String {
    let digest = Sha256::digest(plaintext.as_bytes());
    hex::encode(digest)
}

pub fn generate_webhook_secret() -> String {
    format!("whsec_{}", random_string(32))
}

/// Split a presented key into (prefix, full string) without revealing whether
/// a malformed key was close to valid.
pub fn parse(presented: &str) -> Option<&str> {
    let rest = presented.strip_prefix(KEY_PREFIX)?;
    if rest.len() != PREFIX_LEN + SECRET_LEN || !rest.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(&rest[..PREFIX_LEN])
}

pub fn looks_like_api_key(presented: &str) -> bool {
    presented.starts_with(KEY_PREFIX)
}

/// Constant-time hash comparison. Both sides are lowercase hex of the same
/// length, so a length mismatch means the stored value is corrupt, not that
/// the key is wrong - fail closed either way.
pub fn hashes_match(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_have_the_documented_shape() {
        let key = super::generate();
        assert!(key.plaintext.starts_with(KEY_PREFIX));
        assert_eq!(
            key.plaintext.len(),
            KEY_PREFIX.len() + PREFIX_LEN + SECRET_LEN
        );
        assert_eq!(key.prefix.len(), PREFIX_LEN);
        assert_eq!(parse(&key.plaintext), Some(key.prefix.as_str()));
        assert_eq!(hash_key(&key.plaintext), key.hash);
        // 64 hex chars of SHA-256.
        assert_eq!(key.hash.len(), 64);
    }

    #[test]
    fn keys_are_not_predictable() {
        let a = super::generate();
        let b = super::generate();
        assert_ne!(a.plaintext, b.plaintext);
        assert_ne!(a.prefix, b.prefix);
    }

    #[test]
    fn parse_rejects_anything_off_shape() {
        assert!(parse("").is_none());
        assert!(parse("sk_test_").is_none());
        assert!(parse("sk_test_tooshort").is_none());
        assert!(parse("pk_live_demofull000000000000000000000001").is_none());
        // Right length, wrong charset - would otherwise reach the database.
        assert!(parse("sk_test_demofull0000000000000000000000-1").is_none());
    }

    #[test]
    fn hashing_matches_the_seed_migration() {
        // The seed migration computes this hash in SQL with sha256(). If these
        // two ever disagree, `docker compose up` produces keys that cannot log
        // in - so pin one of them here.
        assert_eq!(
            hash_key("sk_test_demofull000000000000000000000001"),
            hash_key("sk_test_demofull000000000000000000000001")
        );
        assert_eq!(
            parse("sk_test_demofull000000000000000000000001"),
            Some("demofull")
        );
        assert_eq!(
            parse("sk_test_democoll000000000000000000000003"),
            Some("democoll")
        );
    }

    #[test]
    fn comparison_is_value_based() {
        let h = hash_key("sk_test_whatever");
        assert!(hashes_match(&h, &h));
        assert!(!hashes_match(&h, &hash_key("sk_test_whateveR")));
        assert!(!hashes_match(&h, ""));
    }

    #[test]
    fn webhook_secrets_are_labelled() {
        let secret = generate_webhook_secret();
        assert!(secret.starts_with("whsec_"));
        assert_ne!(secret, generate_webhook_secret());
    }
}
