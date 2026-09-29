/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! Node-auth validation for TPM-backed Scout and DPU-agent JWTs.
//!
//! A node's ES256 signing key never leaves its TPM. Discovery registers the
//! public key only after an EK/AK credential challenge and `TPM2_Certify`
//! prove that the TPM holds that exact key. JWT verification therefore looks
//! up `kid` in the local key registry; it intentionally does not accept the
//! former certificate-backed `x5c` token format.

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use carbide_authn::middleware::BearerTokenAuthenticator;
use data_encoding::BASE64URL_NOPAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use crate::cfg::file::NodeAuthConfig;

#[derive(Debug, thiserror::Error)]
pub(crate) enum NodeAuthError {
    #[error("could not load TPM node-auth keys: {0}")]
    Database(#[from] db::DatabaseError),
    #[error("could not acquire a database connection for TPM node-auth keys: {0}")]
    DatabaseAcquire(#[from] sqlx::Error),
}

/// Why a presented bearer token was rejected. It is logged only at debug;
/// token contents are never logged.
#[derive(Debug, thiserror::Error)]
enum RejectReason {
    #[error("malformed JWT: {0}")]
    Malformed(jsonwebtoken::errors::Error),
    #[error("unexpected algorithm {0:?}; only ES256 is accepted")]
    Algorithm(Algorithm),
    #[error("certificate-backed x5c node JWTs are no longer accepted")]
    LegacyCertificateToken,
    #[error("node JWT has no key id")]
    NoKeyId,
    #[error("node JWT key is not registered")]
    UnknownKey,
    #[error("JWT signature or claims validation failed: {0}")]
    Claims(jsonwebtoken::errors::Error),
    #[error("token lifetime exceeds the allowed maximum")]
    Lifetime,
    #[error("system clock is before the UNIX epoch")]
    Clock,
}

#[derive(Debug, Deserialize)]
struct NodeClaims {
    iat: u64,
    exp: u64,
}

#[derive(Clone)]
struct RegisteredNodeKey {
    machine_spiffe_uri: String,
    public_key: Vec<u8>,
}

/// Validates node JWTs against keys whose TPM certification completed during
/// discovery. The cache avoids database access on every RPC and is refreshed
/// by the API startup task; discovery also updates the local process eagerly.
pub(crate) struct NodeJwtValidator {
    keys: RwLock<HashMap<String, RegisteredNodeKey>>,
    install_generation: AtomicU64,
    machine_spiffe_prefix: String,
    validation: Validation,
    max_token_ttl_sec: u64,
}

impl NodeJwtValidator {
    pub(crate) async fn from_database(
        database: &PgPool,
        cfg: &NodeAuthConfig,
        machine_spiffe_prefix: String,
    ) -> Result<Self, NodeAuthError> {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[::rpc::node_jwt::NODE_JWT_AUDIENCE]);
        validation.set_required_spec_claims(&["exp", "iat", "aud"]);

        let validator = Self {
            keys: RwLock::new(HashMap::new()),
            install_generation: AtomicU64::new(0),
            machine_spiffe_prefix,
            validation,
            max_token_ttl_sec: u64::from(cfg.max_token_ttl_sec),
        };
        validator.refresh(database).await?;
        Ok(validator)
    }

    /// Replaces the complete cache from the database. Callers retain the last
    /// good cache if this fails, so a transient DB error cannot disarm node
    /// authentication for already enrolled machines.
    pub(crate) async fn refresh(&self, database: &PgPool) -> Result<(), NodeAuthError> {
        loop {
            let install_generation = self.install_generation.load(Ordering::Acquire);
            let mut connection = database.acquire().await?;
            let keys = db::node_auth_key::list_keys(&mut connection).await?;
            let mut replacement = HashMap::with_capacity(keys.len());
            for key in keys {
                if key.key_id != key_id(&key.public_key) {
                    tracing::error!(
                        target: "node_auth",
                        machine_id = %key.machine_id,
                        "node-auth: ignoring database key whose id does not match its public key"
                    );
                    continue;
                }
                replacement.insert(
                    key.key_id,
                    RegisteredNodeKey {
                        machine_spiffe_uri: format!(
                            "{}{}",
                            self.machine_spiffe_prefix, key.machine_id
                        ),
                        public_key: key.public_key,
                    },
                );
            }
            let mut cached_keys = self
                .keys
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.install_generation.load(Ordering::Acquire) == install_generation {
                *cached_keys = replacement;
                return Ok(());
            }
        }
    }

    /// Installs a just-certified key in the local API process immediately;
    /// other replicas learn it on their bounded refresh interval.
    pub(crate) fn install(
        &self,
        machine_id: &carbide_uuid::machine::MachineId,
        registered_key_id: String,
        public_key: Vec<u8>,
    ) {
        if registered_key_id != key_id(&public_key) {
            tracing::error!(target: "node_auth", %machine_id, "node-auth: refusing to install malformed TPM key");
            return;
        }
        self.keys
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                registered_key_id,
                RegisteredNodeKey {
                    machine_spiffe_uri: format!("{}{}", self.machine_spiffe_prefix, machine_id),
                    public_key,
                },
            );
        self.install_generation.fetch_add(1, Ordering::Release);
    }

    fn validate(&self, token: &str) -> Result<String, RejectReason> {
        let header = decode_header(token).map_err(RejectReason::Malformed)?;
        if header.alg != Algorithm::ES256 {
            return Err(RejectReason::Algorithm(header.alg));
        }
        if header.x5c.is_some() {
            return Err(RejectReason::LegacyCertificateToken);
        }
        let key_id = header.kid.ok_or(RejectReason::NoKeyId)?;
        let key = self
            .keys
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key_id)
            .cloned()
            .ok_or(RejectReason::UnknownKey)?;
        let decoding_key = DecodingKey::from_ec_der(&key.public_key);
        let claims = decode::<NodeClaims>(token, &decoding_key, &self.validation)
            .map_err(RejectReason::Claims)?
            .claims;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RejectReason::Clock)?
            .as_secs();
        let skew = self.validation.leeway;
        if claims.iat > claims.exp
            || claims.iat > now + skew
            || claims.exp - claims.iat > self.max_token_ttl_sec
            || claims.exp > now + self.max_token_ttl_sec + skew
        {
            return Err(RejectReason::Lifetime);
        }
        Ok(key.machine_spiffe_uri)
    }
}

impl BearerTokenAuthenticator for NodeJwtValidator {
    fn spiffe_id_from_bearer(&self, token: &str) -> Option<String> {
        match self.validate(token) {
            Ok(spiffe_uri) => Some(spiffe_uri),
            Err(reason) => {
                tracing::debug!(target: "node_auth", %reason, "node-auth: rejected bearer token");
                None
            }
        }
    }
}

pub(crate) fn key_id(public_key: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(public_key))
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use jsonwebtoken::{EncodingKey, Header};
    use p256::SecretKey;
    use p256::elliptic_curve::Generate;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use serde::Serialize;

    use super::*;

    const PREFIX: &str = "spiffe://forge.local/forge-system/machine/";

    #[derive(Serialize)]
    struct Claims {
        aud: &'static str,
        iat: u64,
        exp: u64,
    }

    fn validator(secret: &SecretKey, machine_id: &str) -> (NodeJwtValidator, String) {
        use p256::elliptic_curve::sec1::ToSec1Point as _;
        let public_key = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
        let key_id = key_id(&public_key);
        let validator = NodeJwtValidator {
            keys: RwLock::new(HashMap::from([(
                key_id.clone(),
                RegisteredNodeKey {
                    machine_spiffe_uri: format!("{PREFIX}{machine_id}"),
                    public_key,
                },
            )])),
            install_generation: AtomicU64::new(0),
            machine_spiffe_prefix: PREFIX.to_string(),
            validation: {
                let mut validation = Validation::new(Algorithm::ES256);
                validation.set_audience(&[::rpc::node_jwt::NODE_JWT_AUDIENCE]);
                validation.set_required_spec_claims(&["exp", "iat", "aud"]);
                validation
            },
            max_token_ttl_sec: 900,
        };
        (validator, key_id)
    }

    fn token(secret: &SecretKey, key_id: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_id.to_string());
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        jsonwebtoken::encode(
            &header,
            &Claims {
                aud: ::rpc::node_jwt::NODE_JWT_AUDIENCE,
                iat: now,
                exp: now + 300,
            },
            &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn random_secret() -> SecretKey {
        SecretKey::generate()
    }

    #[test]
    fn accepts_a_registered_tpm_key() {
        let secret = random_secret();
        let (validator, key_id) = validator(&secret, "machine-1");
        assert_eq!(
            validator
                .spiffe_id_from_bearer(&token(&secret, &key_id))
                .as_deref(),
            Some("spiffe://forge.local/forge-system/machine/machine-1")
        );
    }

    #[test]
    fn rejects_an_unknown_key_id() {
        let secret = random_secret();
        let (validator, _) = validator(&secret, "machine-1");
        assert!(
            validator
                .spiffe_id_from_bearer(&token(&secret, "not-registered"))
                .is_none()
        );
    }

    #[test]
    fn rejects_the_removed_x5c_format() {
        let secret = random_secret();
        let (validator, key_id) = validator(&secret, "machine-1");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_id);
        header.x5c = Some(vec![BASE64URL_NOPAD.encode(b"not-a-certificate")]);
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let token = jsonwebtoken::encode(
            &header,
            &Claims {
                aud: ::rpc::node_jwt::NODE_JWT_AUDIENCE,
                iat: now,
                exp: now + 300,
            },
            &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap();
        assert!(validator.spiffe_id_from_bearer(&token).is_none());
    }
}
