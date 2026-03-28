use crate::config::JwtConfig;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

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
}

const JWKS_TTL: Duration = Duration::from_secs(300);

impl JwtValidator {
    pub fn new(config: JwtConfig) -> Self {
        Self { config, jwks_cache: Mutex::new(None) }
    }

    /// Validate a raw Bearer token and return the agent identity extracted
    /// from the configured `agent_claim`. Returns an error string on failure.
    pub async fn validate(&self, token: &str) -> Result<String, String> {
        if let Some(secret) = &self.config.secret {
            self.validate_hmac(token, secret)
        } else if self.config.jwks_url.is_some() {
            self.validate_jwks(token).await
        } else {
            Err("no JWT secret or jwks_url configured".to_string())
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

    async fn get_jwks(&self) -> Result<Arc<JwkSet>, String> {
        let url = self.config.jwks_url.as_ref().unwrap();

        {
            let cache = self.jwks_cache.lock().await;
            if let Some(c) = &*cache {
                if c.fetched_at.elapsed() < JWKS_TTL {
                    return Ok(Arc::new(c.keys.clone()));
                }
            }
        }

        // Fetch fresh JWKS
        let body = reqwest::get(url)
            .await
            .map_err(|e| format!("JWKS fetch failed: {e}"))?
            .text()
            .await
            .map_err(|e| format!("JWKS read failed: {e}"))?;

        let keys: JwkSet =
            serde_json::from_str(&body).map_err(|e| format!("JWKS parse failed: {e}"))?;

        let result = Arc::new(keys.clone());
        *self.jwks_cache.lock().await = Some(JwksCache { keys, fetched_at: Instant::now() });
        tracing::info!(url, "JWKS refreshed");

        Ok(result)
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    fn apply_validation_options(&self, v: &mut Validation) {
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
