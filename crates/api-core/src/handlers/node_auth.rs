/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! Enrollment of TPM-held node JWT keys.
//!
//! Discovery first records the EK certificate and issues a MakeCredential
//! challenge for an ephemeral AK. The node answers by certifying its durable
//! ES256 signing key with that AK. Only then can the key identify a node JWT.

use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineId;
use model::hardware_info::TpmEkCertificate;
use sha2::Digest as _;
use tonic::{Request, Response, Status};

use crate::api::Api;
use crate::handlers::utils::convert_and_log_machine_id;
use crate::{CarbideError, attestation as attest};

const CREDENTIAL_SIZE: usize = 32;
const CHALLENGE_MAX_AGE: chrono::TimeDelta = chrono::TimeDelta::minutes(10);

/// Validates public data before the discovery transaction vends a TPM
/// credential challenge. The later certification proves that the TPM owns the
/// data; these checks make malformed input fail at the right API boundary.
pub(super) fn validate_discovery_key(key: &rpc::NodeAuthPublicKey) -> Result<(), CarbideError> {
    if key.key_id != crate::node_auth::key_id(&key.public_key) {
        return Err(CarbideError::InvalidArgument(
            "node-auth public-key id does not match the public key".to_string(),
        ));
    }
    p256::PublicKey::from_sec1_bytes(&key.public_key).map_err(|error| {
        CarbideError::InvalidArgument(format!("node-auth public key is not P-256: {error}"))
    })?;
    if key.key_name.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "node-auth TPM key name is not populated".to_string(),
        ));
    }
    validate_tpm_public(key)?;
    let attest_key_info = key.attest_key_info.as_ref().ok_or_else(|| {
        CarbideError::InvalidArgument("node-auth EK/AK information is not populated".to_string())
    })?;
    if attest_key_info.ek_pub.is_empty()
        || attest_key_info.ak_pub.is_empty()
        || attest_key_info.ak_name.is_empty()
    {
        return Err(CarbideError::InvalidArgument(
            "node-auth EK/AK information contains an empty field".to_string(),
        ));
    }
    validate_attestation_key(attest_key_info)?;
    Ok(())
}

#[cfg(feature = "linux-build")]
fn require_tpm_generated_signing_key(
    public: &tss_esapi::structures::Public,
) -> Result<(), CarbideError> {
    let attributes = public.object_attributes();
    if !attributes.fixed_tpm()
        || !attributes.fixed_parent()
        || !attributes.sensitive_data_origin()
        || !attributes.sign_encrypt()
        || attributes.decrypt()
        || attributes.restricted()
    {
        return Err(CarbideError::InvalidArgument(
            "node-auth TPM key is not a TPM-generated unrestricted signing key".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "linux-build")]
fn expected_tpm_name(tpm_public: &[u8]) -> Vec<u8> {
    let mut name = Vec::with_capacity(34);
    name.extend_from_slice(&0x000bu16.to_be_bytes());
    name.extend_from_slice(&sha2::Sha256::digest(tpm_public));
    name
}

#[cfg(feature = "linux-build")]
fn validate_tpm_public(key: &rpc::NodeAuthPublicKey) -> Result<(), CarbideError> {
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::interface_types::ecc::EccCurve;
    use tss_esapi::structures::{EccScheme, HashScheme, Public};
    use tss_esapi::traits::UnMarshall;

    let public = Public::unmarshall(&key.tpm_public).map_err(|error| {
        CarbideError::InvalidArgument(format!("node-auth TPM public area is malformed: {error}"))
    })?;
    let Public::Ecc {
        name_hashing_algorithm,
        parameters,
        ref unique,
        ..
    } = public
    else {
        return Err(CarbideError::InvalidArgument(
            "node-auth TPM public area is not an ECC key".to_string(),
        ));
    };
    if name_hashing_algorithm != HashingAlgorithm::Sha256
        || parameters.ecc_curve() != EccCurve::NistP256
        || parameters.ecc_scheme() != EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256))
    {
        return Err(CarbideError::InvalidArgument(
            "node-auth TPM public area is not an ES256 signing key".to_string(),
        ));
    }
    require_tpm_generated_signing_key(&public)?;
    let x = unique.x().value();
    let y = unique.y().value();
    if x.len() > 32 || y.len() > 32 {
        return Err(CarbideError::InvalidArgument(
            "node-auth TPM public area has an invalid P-256 coordinate".to_string(),
        ));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend(std::iter::repeat_n(0, 32 - x.len()));
    sec1.extend_from_slice(x);
    sec1.extend(std::iter::repeat_n(0, 32 - y.len()));
    sec1.extend_from_slice(y);
    if sec1 != key.public_key {
        return Err(CarbideError::InvalidArgument(
            "node-auth TPM public area does not match the JWT public key".to_string(),
        ));
    }
    if expected_tpm_name(&key.tpm_public) != key.key_name {
        return Err(CarbideError::InvalidArgument(
            "node-auth TPM public area does not match the TPM key name".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(feature = "linux-build"))]
fn validate_tpm_public(_key: &rpc::NodeAuthPublicKey) -> Result<(), CarbideError> {
    Err(CarbideError::NotImplemented)
}

#[cfg(feature = "linux-build")]
fn validate_attestation_key(
    attest_key_info: &::rpc::machine_discovery::AttestKeyInfo,
) -> Result<(), CarbideError> {
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::structures::{HashScheme, Public, RsaScheme};
    use tss_esapi::traits::UnMarshall;

    let public = Public::unmarshall(&attest_key_info.ak_pub).map_err(|error| {
        CarbideError::InvalidArgument(format!("node-auth AK public area is malformed: {error}"))
    })?;
    let Public::Rsa {
        name_hashing_algorithm,
        parameters,
        ..
    } = &public
    else {
        return Err(CarbideError::InvalidArgument(
            "node-auth AK public area is not an RSA key".to_string(),
        ));
    };
    let attributes = public.object_attributes();
    if *name_hashing_algorithm != HashingAlgorithm::Sha256
        || parameters.rsa_scheme() != RsaScheme::RsaPss(HashScheme::new(HashingAlgorithm::Sha256))
        || !attributes.fixed_tpm()
        || !attributes.fixed_parent()
        || !attributes.sensitive_data_origin()
        || !attributes.restricted()
        || !attributes.sign_encrypt()
        || attributes.decrypt()
    {
        return Err(CarbideError::InvalidArgument(
            "node-auth AK is not a TPM-generated restricted RSA-PSS-SHA256 signing key".to_string(),
        ));
    }
    if expected_tpm_name(&attest_key_info.ak_pub) != attest_key_info.ak_name {
        return Err(CarbideError::InvalidArgument(
            "node-auth AK public area does not match the TPM AK name".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(feature = "linux-build"))]
fn validate_attestation_key(
    _attest_key_info: &::rpc::machine_discovery::AttestKeyInfo,
) -> Result<(), CarbideError> {
    Err(CarbideError::NotImplemented)
}

pub(super) async fn create_key_challenge(
    txn: &mut sqlx::PgConnection,
    key: &rpc::NodeAuthPublicKey,
    machine_id: &MachineId,
    tpm_ek_certificate: &TpmEkCertificate,
) -> Result<rpc::NodeAuthKeyChallenge, Status> {
    validate_discovery_key(key)?;
    let attest_key_info = key.attest_key_info.as_ref().ok_or_else(|| {
        CarbideError::InvalidArgument("node-auth EK/AK information is not populated".to_string())
    })?;

    let ek_sha256 = sha2::Sha256::digest(tpm_ek_certificate.as_bytes());
    let ek_status =
        db::attestation::ek_cert_verification_status::get_by_ek_sha256(&mut *txn, &ek_sha256)
            .await?
            .ok_or_else(|| {
                CarbideError::FailedPrecondition(format!(
                    "TPM EK certificate for {machine_id} was not recorded during discovery"
                ))
            })?;
    if !ek_status.signing_ca_found {
        return Err(CarbideError::FailedPrecondition(format!(
            "TPM EK certificate for {machine_id} is not signed by a configured TPM CA"
        ))
        .into());
    }

    let (matches_certificate, ek_public_key) =
        attest::measured_boot::compare_ek_pub_against_certificate(
            tpm_ek_certificate,
            &attest_key_info.ek_pub,
        )?;
    if !matches_certificate {
        return Err(CarbideError::AttestBindKeyError(
            "certificate's public key did not match node-auth EK public key".to_string(),
        )
        .into());
    }

    let credential: [u8; CREDENTIAL_SIZE] = rand::random();
    let ak_name = attest_key_info.ak_name.clone();
    let (cred_blob, encrypted_secret) = tokio::task::spawn_blocking(move || {
        attest::measured_boot::cli_make_cred(ek_public_key, &ak_name, &credential)
    })
    .await
    .map_err(|error| {
        CarbideError::internal(format!("node-auth makecredential task failed: {error}"))
    })??;
    db::node_auth_key::delete_challenges_for_machine(txn, machine_id).await?;
    db::node_auth_key::insert_challenge(
        txn,
        &db::node_auth_key::NodeAuthKeyChallenge {
            credential: credential.to_vec(),
            machine_id: *machine_id,
            ak_pub: attest_key_info.ak_pub.clone(),
            key_id: key.key_id.clone(),
            public_key: key.public_key.clone(),
            key_name: key.key_name.clone(),
            created_at: chrono::Utc::now(),
        },
    )
    .await?;

    Ok(rpc::NodeAuthKeyChallenge {
        cred_blob,
        encrypted_secret,
    })
}

#[cfg(feature = "linux-build")]
pub(crate) async fn register_key(
    api: &Api,
    request: Request<rpc::RegisterNodeAuthKeyRequest>,
) -> Result<Response<rpc::RegisterNodeAuthKeyResponse>, Status> {
    use tss_esapi::structures::{Attest, AttestInfo};
    use tss_esapi::traits::UnMarshall;

    let request = request.into_inner();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;
    if request.credential.len() != CREDENTIAL_SIZE {
        return Err(CarbideError::InvalidArgument(
            "node-auth credential has an invalid length".to_string(),
        )
        .into());
    }

    let mut txn = api.txn_begin().await?;
    let challenge = db::node_auth_key::get_challenge(&mut txn, &request.credential)
        .await?
        .ok_or_else(|| {
            CarbideError::FailedPrecondition(
                "node-auth credential is unknown, expired, or already used".to_string(),
            )
        })?;
    if challenge.machine_id != machine_id {
        return Err(CarbideError::PermissionDeniedError(
            "node-auth credential belongs to another machine".to_string(),
        )
        .into());
    }
    if chrono::Utc::now() - challenge.created_at > CHALLENGE_MAX_AGE {
        return Err(CarbideError::FailedPrecondition(
            "node-auth credential has expired".to_string(),
        )
        .into());
    }

    if !attest::verify_signature(&challenge.ak_pub, &request.attestation, &request.signature)? {
        return Err(CarbideError::PermissionDeniedError(
            "node-auth TPM certification signature is invalid".to_string(),
        )
        .into());
    }
    let attestation = Attest::unmarshall(&request.attestation).map_err(|error| {
        CarbideError::InvalidArgument(format!("node-auth TPM certification is malformed: {error}"))
    })?;
    let AttestInfo::Certify { info } = attestation.attested() else {
        return Err(CarbideError::InvalidArgument(
            "node-auth TPM evidence is not a certify attestation".to_string(),
        )
        .into());
    };
    if attestation.extra_data().value() != request.credential
        || info.name().value() != challenge.key_name
    {
        return Err(CarbideError::PermissionDeniedError(
            "node-auth TPM certification does not bind the enrollment challenge and signing key"
                .to_string(),
        )
        .into());
    }

    db::node_auth_key::upsert_key(
        &mut txn,
        &db::node_auth_key::NodeAuthKey {
            machine_id,
            key_id: challenge.key_id.clone(),
            public_key: challenge.public_key.clone(),
            key_name: challenge.key_name,
        },
    )
    .await?;
    db::node_auth_key::delete_challenge(&mut txn, &request.credential).await?;
    txn.commit().await?;

    if let Some(validator) = &api.node_jwt_validator {
        validator.install(&machine_id, challenge.key_id, challenge.public_key);
    }
    tracing::info!(%machine_id, "node-auth: enrolled TPM JWT signing key");
    Ok(Response::new(rpc::RegisterNodeAuthKeyResponse {}))
}

#[cfg(not(feature = "linux-build"))]
pub(crate) async fn register_key(
    _api: &Api,
    _request: Request<rpc::RegisterNodeAuthKeyRequest>,
) -> Result<Response<rpc::RegisterNodeAuthKeyResponse>, Status> {
    Err(CarbideError::NotImplemented.into())
}
