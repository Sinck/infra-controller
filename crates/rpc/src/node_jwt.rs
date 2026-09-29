/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! TPM-backed node-auth JWT minting and request authentication.
//!
//! Scout and DPU-agent sign short-lived ES256 JWTs with a P-256 key that
//! never leaves their host TPM or DPU fTPM. Discovery enrolls the public key
//! through an EK/AK credential challenge, so tokens carry only a `kid` and
//! never an `x5c` certificate chain or a caller-selected identity claim.

use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest as _, Sha256};
use tower::Service;

use crate::node_tpm::{self, DEFAULT_NODE_AUTH_TPM_PATH};

/// `aud` claim stamped on all node-auth tokens.
pub const NODE_JWT_AUDIENCE: &str = "nico-api";

/// Lifetime of minted tokens. Deliberately short: tokens cost nothing to
/// re-mint locally, so a leaked one ages out in minutes.
pub const NODE_JWT_TTL_SECS: u64 = 300;

/// A cached token is reused until it has less than this long left, then
/// re-minted. Comfortably above per-request latency, comfortably below TTL.
const REMINT_MARGIN_SECS: u64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum NodeJwtError {
    #[error("system clock is before the UNIX epoch")]
    Clock,
    #[error("TPM-backed node key is unavailable: {0}")]
    Tpm(#[from] node_tpm::NodeTpmError),
    #[error("could not serialize node JWT: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: u64,
}

/// Mints node-auth JWTs with the DPU fTPM or host TPM. It emits no `x5c`
/// header: the API looks up the JWT `kid` in the TPM-certified machine-key
/// registry created during discovery.
pub struct TpmNodeJwtMinter {
    tpm_path: String,
    cached: RwLock<Option<CachedToken>>,
}

impl std::fmt::Debug for TpmNodeJwtMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmNodeJwtMinter")
            .field("tpm_path", &self.tpm_path)
            .finish_non_exhaustive()
    }
}

impl TpmNodeJwtMinter {
    #[must_use]
    pub fn new(tpm_path: String) -> Arc<Self> {
        Arc::new(Self {
            tpm_path,
            cached: RwLock::new(None),
        })
    }

    /// Convenience constructor for DPU-agent, whose runtime TPM is exposed
    /// through the kernel resource-manager device.
    #[must_use]
    pub fn with_default_tpm() -> Arc<Self> {
        Self::new(DEFAULT_NODE_AUTH_TPM_PATH.to_string())
    }

    /// Returns the public identity that discovery must enroll before this
    /// minter's tokens become useful to the API.
    pub fn public_key(&self) -> Result<node_tpm::NodeAuthPublicKey, NodeJwtError> {
        node_tpm::node_auth_public_key(&self.tpm_path).map_err(NodeJwtError::Tpm)
    }

    /// Gets a valid cached token or signs a replacement in the TPM.
    pub fn current_with_expiry(&self) -> Option<(String, u64)> {
        let now = unix_now().ok()?;
        if let Some(cached) = self
            .cached
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            && cached.expires_at > now + REMINT_MARGIN_SECS
        {
            return Some((cached.token.clone(), cached.expires_at));
        }
        match self.mint(now) {
            Ok(minted) => {
                let result = (minted.token.clone(), minted.expires_at);
                *self
                    .cached
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(minted);
                Some(result)
            }
            Err(error) => {
                tracing::debug!(
                    target: "node_auth",
                    tpm_path = %self.tpm_path,
                    %error,
                    "node-auth: could not mint TPM-backed node JWT"
                );
                None
            }
        }
    }

    fn mint(&self, now: u64) -> Result<CachedToken, NodeJwtError> {
        let public_key = self.public_key()?;
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": public_key.key_id,
        });
        let expires_at = now + NODE_JWT_TTL_SECS;
        // Identity is deliberately not a JWT claim. The API derives it from
        // the enrolled TPM key, preventing a client from choosing another
        // machine's SPIFFE identifier.
        let claims = serde_json::json!({
            "aud": NODE_JWT_AUDIENCE,
            "iat": now,
            "exp": expires_at,
        });
        let signing_input = format!(
            "{}.{}",
            BASE64URL_NOPAD.encode(&serde_json::to_vec(&header)?),
            BASE64URL_NOPAD.encode(&serde_json::to_vec(&claims)?),
        );
        let digest = Sha256::digest(signing_input.as_bytes());
        let signature = node_tpm::sign_sha256(&self.tpm_path, &digest)?;
        let token = format!("{signing_input}.{}", BASE64URL_NOPAD.encode(&signature));
        Ok(CachedToken { token, expires_at })
    }
}

fn unix_now() -> Result<u64, NodeJwtError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| NodeJwtError::Clock)
}

/// A source of node-auth bearer tokens for outgoing requests.
///
/// `current` runs on the request path, so implementations must return
/// promptly and never wait on a network or remote peer. `TpmNodeJwtMinter`
/// signs locally only on a cache miss; `SocketTokenSource` fetches from the
/// DPU agent in a background task and serves its cached result here.
pub trait NodeTokenProvider: Send + Sync + std::fmt::Debug {
    /// Returns a currently-valid token, or `None` when one is unavailable.
    fn current(&self) -> Option<String>;
}

impl NodeTokenProvider for TpmNodeJwtMinter {
    fn current(&self) -> Option<String> {
        self.current_with_expiry().map(|(token, _)| token)
    }
}

/// A node-token provider that can also report token expiry. The DPU agent
/// uses this to broker its TPM-minted token to local consumers without giving
/// them access to the TPM signing key.
pub trait NodeTokenMinter: NodeTokenProvider {
    /// Returns a currently-valid token and its UNIX expiry time.
    fn current_with_expiry(&self) -> Option<(String, u64)>;
}

impl NodeTokenMinter for TpmNodeJwtMinter {
    fn current_with_expiry(&self) -> Option<(String, u64)> {
        TpmNodeJwtMinter::current_with_expiry(self)
    }
}

/// Tower middleware that injects `Authorization: Bearer <jwt>` onto each
/// request when a [`NodeTokenProvider`] is configured. A `None` provider is a
/// no-op, so the same client construction path serves both token and
/// mTLS-only modes.
#[derive(Clone)]
pub struct BearerAuthService<S> {
    inner: S,
    minter: Option<Arc<dyn NodeTokenProvider>>,
}

impl<S> BearerAuthService<S> {
    pub fn new(inner: S, minter: Option<Arc<dyn NodeTokenProvider>>) -> Self {
        Self { inner, minter }
    }
}

impl<S, B> Service<hyper::Request<B>> for BearerAuthService<S>
where
    S: Service<hyper::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: hyper::Request<B>) -> Self::Future {
        if let Some(value) = self
            .minter
            .as_ref()
            .and_then(|minter| minter.current())
            .and_then(|token| hyper::http::HeaderValue::from_str(&format!("Bearer {token}")).ok())
        {
            request
                .headers_mut()
                .insert(hyper::header::AUTHORIZATION, value);
        }
        self.inner.call(request)
    }
}
