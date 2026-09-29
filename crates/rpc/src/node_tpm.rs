/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! TPM-resident signing material for node-auth.
//!
//! The node-auth key is an ECC primary object in the Owner hierarchy.  A
//! primary object's private half is derived inside the TPM from its hierarchy
//! seed and template, so recreating this exact object after a restart gives
//! the same non-exportable key without placing a private-key blob on disk.
//! Clearing the TPM changes the hierarchy seed and deliberately produces a
//! new key which must be enrolled again.

use std::str::FromStr;

use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest as _, Sha256};
use tss_esapi::abstraction::{AsymmetricAlgorithmSelection, ak, ek};
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{
    AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Data, Digest as TpmDigest, EccScheme, HashScheme, Public, Signature, SignatureScheme,
};
use tss_esapi::traits::Marshall;
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::{Context, TctiNameConf};

/// Normal TCTI for both a host TPM and the DPU fTPM.
pub const DEFAULT_NODE_AUTH_TPM_PATH: &str = "device:/dev/tpmrm0";

/// Public component registered with nico-api during discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeAuthPublicKey {
    /// SHA-256 of the uncompressed P-256 point, encoded for the JWT `kid`.
    pub key_id: String,
    /// Uncompressed SEC1 P-256 point, suitable for ES256 verification.
    pub public_key: Vec<u8>,
    /// TPM name of the signing object.  The AK certification binds this name
    /// to the object the TPM actually loaded.
    pub key_name: Vec<u8>,
    /// Marshalled TPMT_PUBLIC. This lets the API bind `key_name` to the exact
    /// P-256 public point that verifies JWTs.
    pub tpm_public: Vec<u8>,
}

/// The TPM objects held only across the enrollment challenge round-trip.
///
/// The AK proves possession of the EK and certifies the separate node-auth
/// signing key.  It must not itself sign JWTs: the AK is RSA-PSS and is
/// intentionally transient, whereas node tokens are ES256 and need a stable
/// signing identity across restarts.
pub struct NodeAuthEnrollment {
    context: Context,
    attestation_key: KeyHandle,
    public_key: NodeAuthPublicKey,
}

impl std::fmt::Debug for NodeAuthEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeAuthEnrollment")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NodeTpmError {
    #[error("invalid TPM TCTI {path}: {error}")]
    Tcti {
        path: String,
        error: tss_esapi::Error,
    },
    #[error("TPM operation failed: {0}")]
    Tpm(#[from] tss_esapi::Error),
    #[error("node-auth TPM key is not a P-256 ECC key")]
    UnexpectedPublicKey,
    #[error("node-auth TPM key has an invalid P-256 coordinate length")]
    InvalidCoordinateLength,
    #[error("TPM produced a non-ECDSA-SHA256 signature")]
    UnexpectedSignature,
    #[error("TPM activation credential was not the expected 32-byte challenge")]
    InvalidCredential,
    #[error("TPM did not create an authorization session")]
    SessionNotCreated,
}

/// Open the TPM, recreate the stable node-auth signing key, and return its
/// public identity.  This is deliberately cheap enough for discovery; token
/// minting only does it once per cache lifetime.
pub fn node_auth_public_key(tpm_path: &str) -> Result<NodeAuthPublicKey, NodeTpmError> {
    let mut context = create_context(tpm_path)?;
    let key_handle = create_node_auth_key(&mut context)?;
    let result = public_key_for_handle(&mut context, key_handle);
    let _ = context.flush_context(key_handle.into());
    result
}

impl NodeAuthEnrollment {
    /// Creates the RSA AK and derives the stable ES256 signing-key identity.
    /// Only the AK remains loaded across the credential round-trip; the EK
    /// and signing primary are deterministically recreated when needed so a
    /// host's concurrent measured-boot flow stays within TPM transient-object
    /// limits.
    pub fn new(tpm_path: &str) -> Result<Self, NodeTpmError> {
        let mut context = create_context(tpm_path)?;
        let endorsement_key = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, None)?;
        let ak = ak::create_ak(
            &mut context,
            endorsement_key,
            HashingAlgorithm::Sha256,
            SignatureSchemeAlgorithm::RsaPss,
            None,
            None,
        )?;
        let attestation_key = ak::load_ak(
            &mut context,
            endorsement_key,
            None,
            ak.out_private,
            ak.out_public,
        )?;
        let node_auth_key = create_node_auth_key(&mut context)?;
        let public_key = public_key_for_handle(&mut context, node_auth_key)?;
        let _ = context.flush_context(node_auth_key.into());
        let _ = context.flush_context(endorsement_key.into());

        Ok(Self {
            context,
            attestation_key,
            public_key,
        })
    }

    /// Existing discovery attestation material used by the API to create a
    /// `MakeCredential` challenge against the TPM's EK and AK.
    pub fn attest_key_info(
        &mut self,
    ) -> Result<crate::machine_discovery::AttestKeyInfo, NodeTpmError> {
        let (ak_public, ak_name, _) = self.context.read_public(self.attestation_key)?;
        let endorsement_key =
            ek::create_ek_object(&mut self.context, AsymmetricAlgorithm::Rsa, None)?;
        let ek_public = self
            .context
            .read_public(endorsement_key)
            .map(|result| result.0);
        let _ = self.context.flush_context(endorsement_key.into());
        let ek_public = ek_public?;

        Ok(crate::machine_discovery::AttestKeyInfo {
            ak_pub: ak_public.marshall()?,
            ak_name: ak_name.value().to_vec(),
            ek_pub: ek_public.marshall()?,
        })
    }

    /// The RSA EK certificate used by the API's existing TPM-CA validation.
    /// This reads the standard TPM NV index directly through ESAPI, so it does
    /// not depend on `tpm2-tools` being present in the DPU OS.
    pub fn ek_certificate(&mut self) -> Result<Vec<u8>, NodeTpmError> {
        ek::retrieve_ek_pubcert(
            &mut self.context,
            AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        )
        .map_err(NodeTpmError::Tpm)
    }

    /// Discovery payload for the API's node-auth enrollment challenge.
    pub fn discovery_public_key(
        &mut self,
    ) -> Result<crate::forge::NodeAuthPublicKey, NodeTpmError> {
        Ok(crate::forge::NodeAuthPublicKey {
            key_id: self.public_key.key_id.clone(),
            public_key: self.public_key.public_key.clone(),
            key_name: self.public_key.key_name.clone(),
            attest_key_info: Some(self.attest_key_info()?),
            tpm_public: self.public_key.tpm_public.clone(),
        })
    }

    #[must_use]
    pub fn public_key(&self) -> &NodeAuthPublicKey {
        &self.public_key
    }

    /// Activates the API's EK/AK credential and uses the recovered nonce as
    /// qualifying data for `TPM2_Certify` over the node-auth signing key.
    /// The returned evidence is verified by the API before it persists the
    /// public key.
    pub fn activate_and_certify(
        &mut self,
        credential_blob: &[u8],
        encrypted_secret: &[u8],
    ) -> Result<NodeAuthCertification, NodeTpmError> {
        let endorsement_key =
            ek::create_ek_object(&mut self.context, AsymmetricAlgorithm::Rsa, None)?;
        let node_auth_key = create_node_auth_key(&mut self.context)?;
        let result = (|| {
            let credential = activate_credential(
                &mut self.context,
                endorsement_key,
                self.attestation_key,
                credential_blob,
                encrypted_secret,
            )?;
            if credential.len() != 32 {
                return Err(NodeTpmError::InvalidCredential);
            }
            let (attestation, signature) = self.context.execute_with_sessions(
                (
                    Some(AuthSession::Password),
                    Some(AuthSession::Password),
                    None,
                ),
                |ctx| {
                    ctx.certify(
                        node_auth_key.into(),
                        self.attestation_key,
                        Data::try_from(credential.clone())?,
                        SignatureScheme::Null,
                    )
                },
            )?;

            Ok(NodeAuthCertification {
                credential,
                attestation: attestation.marshall()?,
                signature: signature.marshall()?,
            })
        })();
        let _ = self.context.flush_context(node_auth_key.into());
        let _ = self.context.flush_context(endorsement_key.into());
        result
    }
}

impl Drop for NodeAuthEnrollment {
    fn drop(&mut self) {
        let _ = self.context.flush_context(self.attestation_key.into());
    }
}

/// Evidence sent to the API after discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeAuthCertification {
    pub credential: Vec<u8>,
    pub attestation: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Signs a SHA-256 digest with the stable TPM-resident ES256 key, returning
/// the fixed-width `r || s` JWS representation.
pub fn sign_sha256(tpm_path: &str, digest: &[u8]) -> Result<Vec<u8>, NodeTpmError> {
    let mut context = create_context(tpm_path)?;
    let key_handle = create_node_auth_key(&mut context)?;
    let validation = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    };
    let signature = context.execute_with_session(Some(AuthSession::Password), |ctx| {
        ctx.sign(
            key_handle,
            TpmDigest::try_from(digest.to_vec())?,
            SignatureScheme::Null,
            validation.try_into()?,
        )
    })?;
    let _ = context.flush_context(key_handle.into());
    jws_signature(signature)
}

fn create_context(tpm_path: &str) -> Result<Context, NodeTpmError> {
    let tcti = TctiNameConf::from_str(tpm_path).map_err(|error| NodeTpmError::Tcti {
        path: tpm_path.to_string(),
        error,
    })?;
    Context::new(tcti).map_err(NodeTpmError::Tpm)
}

fn create_node_auth_key(context: &mut Context) -> Result<KeyHandle, NodeTpmError> {
    let public = tss_esapi::utils::create_unrestricted_signing_ecc_public(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )?;
    context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .map(|result| result.key_handle)
        .map_err(NodeTpmError::Tpm)
}

fn public_key_for_handle(
    context: &mut Context,
    key_handle: KeyHandle,
) -> Result<NodeAuthPublicKey, NodeTpmError> {
    let (public, key_name, _) = context.read_public(key_handle)?;
    let public_key = sec1_public_key(&public)?;
    let key_id = BASE64URL_NOPAD.encode(&Sha256::digest(&public_key));
    Ok(NodeAuthPublicKey {
        key_id,
        public_key,
        key_name: key_name.value().to_vec(),
        tpm_public: public.marshall()?,
    })
}

fn sec1_public_key(public: &Public) -> Result<Vec<u8>, NodeTpmError> {
    let Public::Ecc { unique, .. } = public else {
        return Err(NodeTpmError::UnexpectedPublicKey);
    };
    let x = unique.x().value();
    let y = unique.y().value();
    if x.len() > 32 || y.len() > 32 {
        return Err(NodeTpmError::InvalidCoordinateLength);
    }

    let mut result = Vec::with_capacity(65);
    result.push(0x04);
    result.extend(std::iter::repeat_n(0, 32 - x.len()));
    result.extend_from_slice(x);
    result.extend(std::iter::repeat_n(0, 32 - y.len()));
    result.extend_from_slice(y);
    Ok(result)
}

fn jws_signature(signature: Signature) -> Result<Vec<u8>, NodeTpmError> {
    let Signature::EcDsa(signature) = signature else {
        return Err(NodeTpmError::UnexpectedSignature);
    };
    if signature.hashing_algorithm() != HashingAlgorithm::Sha256 {
        return Err(NodeTpmError::UnexpectedSignature);
    }
    let r = signature.signature_r().value();
    let s = signature.signature_s().value();
    if r.len() > 32 || s.len() > 32 {
        return Err(NodeTpmError::UnexpectedSignature);
    }
    let mut encoded = Vec::with_capacity(64);
    encoded.extend(std::iter::repeat_n(0, 32 - r.len()));
    encoded.extend_from_slice(r);
    encoded.extend(std::iter::repeat_n(0, 32 - s.len()));
    encoded.extend_from_slice(s);
    Ok(encoded)
}

fn activate_credential(
    context: &mut Context,
    endorsement_key: KeyHandle,
    attestation_key: KeyHandle,
    credential_blob: &[u8],
    encrypted_secret: &[u8],
) -> Result<Vec<u8>, NodeTpmError> {
    use tss_esapi::attributes::session::SessionAttributesBuilder;
    use tss_esapi::constants::SessionType;
    use tss_esapi::handles::{AuthHandle, SessionHandle};
    use tss_esapi::interface_types::session_handles::PolicySession;
    use tss_esapi::structures::{EncryptedSecret, IdObject, SymmetricDefinition};

    let credential_blob = IdObject::try_from(credential_blob)?;
    let encrypted_secret = EncryptedSecret::try_from(encrypted_secret)?;
    let endorsement_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(NodeTpmError::SessionNotCreated)?;
    let ak_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(NodeTpmError::SessionNotCreated)?;
    let (attributes, attribute_mask) = SessionAttributesBuilder::new().build();
    context.tr_sess_set_attributes(endorsement_session, attributes, attribute_mask)?;
    context.tr_sess_set_attributes(ak_session, attributes, attribute_mask)?;
    context.execute_with_session(Some(ak_session), |ctx| {
        ctx.policy_secret(
            PolicySession::try_from(endorsement_session)?,
            AuthHandle::Endorsement,
            Default::default(),
            Default::default(),
            Default::default(),
            None,
        )
    })?;
    let credential = {
        context.set_sessions((Some(ak_session), Some(endorsement_session), None));
        context.activate_credential(
            attestation_key,
            endorsement_key,
            credential_blob,
            encrypted_secret,
        )
    };
    context.clear_sessions();
    let _ = context.flush_context(SessionHandle::from(ak_session).into());
    let _ = context.flush_context(SessionHandle::from(endorsement_session).into());
    Ok(credential?.value().to_vec())
}
