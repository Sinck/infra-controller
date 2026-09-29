/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! Persistence for TPM-backed node-auth keys.

use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgConnection};

use crate::{DatabaseError, DatabaseResult};

#[derive(Clone, Debug, FromRow)]
pub struct NodeAuthKey {
    pub machine_id: MachineId,
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub key_name: Vec<u8>,
}

#[derive(Clone, Debug, FromRow)]
pub struct NodeAuthKeyChallenge {
    pub credential: Vec<u8>,
    pub machine_id: MachineId,
    pub ak_pub: Vec<u8>,
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub key_name: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_challenge(
    txn: &mut PgConnection,
    challenge: &NodeAuthKeyChallenge,
) -> DatabaseResult<()> {
    const QUERY: &str = r#"
        INSERT INTO node_auth_key_challenges
            (credential, machine_id, ak_pub, key_id, public_key, key_name, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    "#;
    sqlx::query(QUERY)
        .bind(&challenge.credential)
        .bind(challenge.machine_id)
        .bind(&challenge.ak_pub)
        .bind(&challenge.key_id)
        .bind(&challenge.public_key)
        .bind(&challenge.key_name)
        .bind(challenge.created_at)
        .execute(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(QUERY, error))?;
    Ok(())
}

pub async fn get_challenge(
    txn: &mut PgConnection,
    credential: &[u8],
) -> DatabaseResult<Option<NodeAuthKeyChallenge>> {
    const QUERY: &str = r#"
        SELECT credential, machine_id, ak_pub, key_id, public_key, key_name, created_at
        FROM node_auth_key_challenges
        WHERE credential = $1
        FOR UPDATE
    "#;
    sqlx::query_as(QUERY)
        .bind(credential)
        .fetch_optional(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(QUERY, error))
}

pub async fn delete_challenge(txn: &mut PgConnection, credential: &[u8]) -> DatabaseResult<()> {
    const QUERY: &str = "DELETE FROM node_auth_key_challenges WHERE credential = $1";
    sqlx::query(QUERY)
        .bind(credential)
        .execute(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(QUERY, error))?;
    Ok(())
}

/// Re-discovery supersedes any unanswered enrollment challenge for the same
/// machine. This bounds challenge retention and makes a TPM clear recover on
/// the next discovery instead of leaving a queue of stale credentials.
pub async fn delete_challenges_for_machine(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> DatabaseResult<()> {
    const QUERY: &str = "DELETE FROM node_auth_key_challenges WHERE machine_id = $1";
    sqlx::query(QUERY)
        .bind(machine_id)
        .execute(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(QUERY, error))?;
    Ok(())
}

pub async fn upsert_key(txn: &mut PgConnection, key: &NodeAuthKey) -> DatabaseResult<()> {
    const DELETE_QUERY: &str = "DELETE FROM node_auth_keys WHERE machine_id = $1 OR key_id = $2";
    sqlx::query(DELETE_QUERY)
        .bind(key.machine_id)
        .bind(&key.key_id)
        .execute(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(DELETE_QUERY, error))?;

    const INSERT_QUERY: &str = r#"
        INSERT INTO node_auth_keys (machine_id, key_id, public_key, key_name)
        VALUES ($1, $2, $3, $4)
    "#;
    sqlx::query(INSERT_QUERY)
        .bind(key.machine_id)
        .bind(&key.key_id)
        .bind(&key.public_key)
        .bind(&key.key_name)
        .execute(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(INSERT_QUERY, error))?;
    Ok(())
}

pub async fn list_keys(txn: &mut PgConnection) -> DatabaseResult<Vec<NodeAuthKey>> {
    const QUERY: &str = "SELECT machine_id, key_id, public_key, key_name FROM node_auth_keys";
    sqlx::query_as(QUERY)
        .fetch_all(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(QUERY, error))
}
