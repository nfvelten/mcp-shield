use crate::config::JwtConfig;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
};
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, time::timeout};

const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const JWKS_TTL: Duration = Duration::from_secs(300);

// ── JWKS cache ────────────────────────────────────────────────────────────────

struct JwksCache {
    keys: JwkSet,
    fetched_at: Instant,
}

/// Stateful JWT validator. Holds the JWKS cache when using OIDC.
pub struct JwtValidator {
    config: JwtConfig,
    /// Cached JWKS — populated lazily and refreshed every 5 minutes.
    jwks_cache: Mutex<Option<JwksCache>>,
    /// Resolved JWKS URL — populated lazily from OIDC discovery when
    /// `oidc_discovery: true` and no explicit `jwks_url` is set.
    resolved_jwks_url: Mutex<Option<String>>,
}

impl JwtValidator {
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config,
            jwks_cache: Mutex::new(None),
            resolved_jwks_url: Mutex::new(None),
        }
    }

    /// Validate a raw Bearer token and return the agent identity extracted
    /// from the configured `agent_claim`. Returns an error string on failure.
    pub async fn validate(&self, token: &str) -> Result<String, String> {
        if let Some(secret) = &self.config.secret {
            self.validate_hmac(token, secret)
        } else {
            self.validate_jwks(token).await
        }
    }

    // ── HMAC (HS256) ──────────────────────────────────────────────────────────

    fn validate_hmac(&self, token: &str, secret: &str) -> Result<String, String> {
        let key = DecodingKey::from_secret(secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        self.apply_validation_options(&mut validation);

        let data = decode::<Value>(token, &key, &validation)
            .map_err(|e| format!("JWT validation failed: {e}"))?;

        self.extract_agent_claim(&data.claims)
    }

    // ── JWKS / OIDC (RS256 / ES256) ───────────────────────────────────────────

    async fn validate_jwks(&self, token: &str) -> Result<String, String> {
        let jwks = self.get_jwks().await?;

        // Find the key matching the JWT's `kid` header
        let header = decode_header(token).map_err(|e| format!("invalid JWT header: {e}"))?;
        let kid = header.kid.as_deref().unwrap_or("");

        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref().unwrap_or("") == kid)
            .ok_or_else(|| format!("no JWKS key found for kid={kid:?}"))?;

        let (key, alg) = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                let key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
                    .map_err(|e| format!("invalid RSA key: {e}"))?;
                (key, Algorithm::RS256)
            }
            AlgorithmParameters::EllipticCurve(ec) => {
                let key = DecodingKey::from_ec_components(&ec.x, &ec.y)
                    .map_err(|e| format!("invalid EC key: {e}"))?;
                (key, Algorithm::ES256)
            }
            other => return Err(format!("unsupported key type: {other:?}")),
        };

        let mut validation = Validation::new(alg);
        self.apply_validation_options(&mut validation);

        let data = decode::<Value>(token, &key, &validation)
            .map_err(|e| format!("JWT validation failed: {e}"))?;

        self.extract_agent_claim(&data.claims)
    }

    /// Resolve the JWKS URL — either directly from config or via OIDC discovery.
    async fn resolve_jwks_url(&self) -> Result<String, String> {
        // Explicit jwks_url takes priority
        if let Some(url) = &self.config.jwks_url {
            return Ok(url.clone());
        }

        if self.config.oidc_discovery {
            // Check discovery cache
            {
                let cached = self.resolved_jwks_url.lock().await;
                if let Some(url) = &*cached {
                    return Ok(url.clone());
                }
            }

            let issuer = self
                .config
                .issuer
                .as_ref()
                .ok_or_else(|| "oidc_discovery requires issuer to be set".to_string())?;

            let url = oidc_discover_jwks(issuer)
                .await
                .map_err(|e| format!("OIDC discovery failed: {e}"))?;

            tracing::info!(issuer, jwks_url = %url, "OIDC discovery completed");
            *self.resolved_jwks_url.lock().await = Some(url.clone());
            return Ok(url);
        }

        Err("no jwks_url configured and oidc_discovery is false".to_string())
    }

    async fn get_jwks(&self) -> Result<Arc<JwkSet>, String> {
        let url = self.resolve_jwks_url().await?;

        {
            let cache = self.jwks_cache.lock().await;
            if let Some(c) = &*cache
                && c.fetched_at.elapsed() < JWKS_TTL
            {
                return Ok(Arc::new(c.keys.clone()));
            }
        }

        // Fetch fresh JWKS — abort if the endpoint doesn't respond in time
        let body = timeout(JWKS_FETCH_TIMEOUT, async {
            reqwest::get(&url)
                .await
                .map_err(|e| format!("JWKS fetch failed: {e}"))?
                .text()
                .await
                .map_err(|e| format!("JWKS read failed: {e}"))
        })
        .await
        .map_err(|_| "JWKS fetch timed out".to_string())??;

        let keys: JwkSet =
            serde_json::from_str(&body).map_err(|e| format!("JWKS parse failed: {e}"))?;

        let result = Arc::new(keys.clone());
        *self.jwks_cache.lock().await = Some(JwksCache {
            keys,
            fetched_at: Instant::now(),
        });
        tracing::info!(url = %url, "JWKS refreshed");

        Ok(result)
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    fn apply_validation_options(&self, v: &mut Validation) {
        // exp is always required — tokens without an expiry are rejected
        v.set_required_spec_claims(&["exp"]);

        if let Some(iss) = &self.config.issuer {
            v.set_issuer(&[iss]);
        }
        if let Some(aud) = &self.config.audience {
            v.set_audience(&[aud]);
        } else {
            v.validate_aud = false;
        }
    }

    fn extract_agent_claim(&self, claims: &Value) -> Result<String, String> {
        claims[&self.config.agent_claim]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                format!(
                    "claim '{}' not found or not a string in JWT",
                    self.config.agent_claim
                )
            })
    }
}

// ── OIDC discovery ────────────────────────────────────────────────────────────

/// Fetch the OIDC discovery document for `issuer` and return the `jwks_uri`.
async fn oidc_discover_jwks(issuer: &str) -> anyhow::Result<String> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let doc: Value = timeout(JWKS_FETCH_TIMEOUT, async {
        reqwest::get(&discovery_url).await?.json::<Value>().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("OIDC discovery timed out for {issuer}"))??;

    doc["jwks_uri"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| anyhow::anyhow!("no jwks_uri in OIDC discovery document at {discovery_url}"))
}

// ── Multi-provider validator ──────────────────────────────────────────────────

/// Tries each configured provider in order — the first that successfully
/// validates the token wins. Used when `auth:` contains a list of providers.
pub struct MultiJwtValidator {
    validators: Vec<JwtValidator>,
}

impl MultiJwtValidator {
    pub fn new(configs: Vec<JwtConfig>) -> Self {
        Self {
            validators: configs.into_iter().map(JwtValidator::new).collect(),
        }
    }

    /// Validate a Bearer token against all configured providers.
    /// Returns the agent identity from the first provider that accepts the token.
    pub async fn validate(&self, token: &str) -> Result<String, String> {
        let mut last_err = "no auth providers configured".to_string();
        for v in &self.validators {
            match v.validate(token).await {
                Ok(id) => return Ok(id),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JwtConfig;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    const SECRET: &str = "test-secret";

    fn make_token(claims: serde_json::Value, secret: &str) -> String {
        encode(
            &Header::default(), // HS256
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn validator(secret: &str) -> JwtValidator {
        JwtValidator::new(JwtConfig {
            secret: Some(secret.to_string()),
            ..JwtConfig::default()
        })
    }

    #[tokio::test]
    async fn valid_hmac_token_returns_agent_id() {
        let token = make_token(
            json!({"sub": "test-agent", "exp": 9_999_999_999u64}),
            SECRET,
        );
        let v = validator(SECRET);
        assert_eq!(v.validate(&token).await.unwrap(), "test-agent");
    }

    #[tokio::test]
    async fn wrong_secret_fails() {
        let token = make_token(
            json!({"sub": "test-agent", "exp": 9_999_999_999u64}),
            SECRET,
        );
        let v = validator("wrong-secret");
        assert!(v.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn expired_token_fails() {
        let token = make_token(json!({"sub": "test-agent", "exp": 1u64}), SECRET);
        let v = validator(SECRET);
        assert!(v.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn token_without_exp_fails() {
        let token = make_token(json!({"sub": "test-agent"}), SECRET);
        let v = validator(SECRET);
        assert!(v.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn neither_secret_nor_jwks_fails() {
        let v = JwtValidator::new(JwtConfig::default());
        let token = make_token(json!({"sub": "a", "exp": 9_999_999_999u64}), SECRET);
        assert!(v.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn custom_agent_claim_extracted() {
        let v = JwtValidator::new(JwtConfig {
            secret: Some(SECRET.to_string()),
            agent_claim: "agent_id".to_string(),
            ..JwtConfig::default()
        });
        let token = make_token(
            json!({"agent_id": "my-agent", "exp": 9_999_999_999u64}),
            SECRET,
        );
        assert_eq!(v.validate(&token).await.unwrap(), "my-agent");
    }

    #[tokio::test]
    async fn missing_agent_claim_fails() {
        let token = make_token(json!({"exp": 9_999_999_999u64}), SECRET);
        let v = validator(SECRET);
        assert!(v.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn non_string_agent_claim_fails() {
        let token = make_token(json!({"sub": 42, "exp": 9_999_999_999u64}), SECRET);
        let v = validator(SECRET);
        assert!(v.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn issuer_mismatch_fails() {
        let v = JwtValidator::new(JwtConfig {
            secret: Some(SECRET.to_string()),
            issuer: Some("https://expected.example.com".to_string()),
            ..JwtConfig::default()
        });
        let token = make_token(
            json!({"sub": "a", "exp": 9_999_999_999u64, "iss": "https://other.example.com"}),
            SECRET,
        );
        assert!(v.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn issuer_match_passes() {
        let v = JwtValidator::new(JwtConfig {
            secret: Some(SECRET.to_string()),
            issuer: Some("https://auth.example.com".to_string()),
            ..JwtConfig::default()
        });
        let token = make_token(
            json!({"sub": "a", "exp": 9_999_999_999u64, "iss": "https://auth.example.com"}),
            SECRET,
        );
        assert_eq!(v.validate(&token).await.unwrap(), "a");
    }

    // ── MultiJwtValidator ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn multi_validator_first_match_wins() {
        let token = make_token(
            json!({"sub": "agent-a", "exp": 9_999_999_999u64}),
            "secret-a",
        );
        let mv = MultiJwtValidator::new(vec![
            JwtConfig {
                secret: Some("secret-b".to_string()),
                ..JwtConfig::default()
            },
            JwtConfig {
                secret: Some("secret-a".to_string()),
                ..JwtConfig::default()
            },
        ]);
        assert_eq!(mv.validate(&token).await.unwrap(), "agent-a");
    }

    #[tokio::test]
    async fn multi_validator_all_fail_returns_err() {
        let token = make_token(json!({"sub": "a", "exp": 9_999_999_999u64}), "other");
        let mv = MultiJwtValidator::new(vec![
            JwtConfig {
                secret: Some("wrong-1".to_string()),
                ..JwtConfig::default()
            },
            JwtConfig {
                secret: Some("wrong-2".to_string()),
                ..JwtConfig::default()
            },
        ]);
        assert!(mv.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn multi_validator_empty_returns_err() {
        let mv = MultiJwtValidator::new(vec![]);
        let token = make_token(json!({"sub": "a", "exp": 9_999_999_999u64}), SECRET);
        assert!(mv.validate(&token).await.is_err());
    }
}
