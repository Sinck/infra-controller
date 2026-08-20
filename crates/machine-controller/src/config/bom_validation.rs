/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use carbide_utils::config::as_std_duration;
use duration_str::deserialize_duration;
use serde::{Deserialize, Serialize};

/// MachineValidation related configuration
#[derive(Default, Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BomValidationConfig {
    /// Whether BOM Validation is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Allow machines without an assigned SKU to bypass BOM validation.
    /// When true, a machine that remains unassigned can proceed without a SKU.
    #[serde(default)]
    pub ignore_unassigned_machines: bool,

    /// Allow machines with assigned SKUs to proceed when SKU validation fails.
    /// A missing SKU found during verification enters SkuMissing and records a health report.
    ///
    /// When false (default), validation failures block allocation by entering failed states.
    ///
    /// When true, a Ready machine whose assigned SKU is missing stays Ready. A SKU mismatch is logged, but the
    /// machine proceeds without recording a SKU validation health report. On a later reconciliation, a machine with
    /// an assigned SKU in SkuMissing or SkuVerificationFailed can leave BOM validation, clearing that report and
    /// resuming normal lifecycle processing.
    /// This does not bypass machines without an assigned SKU; use ignore_unassigned_machines for that.
    #[serde(default)]
    pub allow_allocation_on_validation_failure: bool,

    /// The interval since the last time the state machine attempted
    /// to find an existing SKU that matches the machine.
    #[serde(
        default = "BomValidationConfig::default_bom_validation_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub find_match_interval: std::time::Duration,

    /// When a SKU is assigned to a machine, but doesn't exist
    /// attempt to create a SKU for the machine.  This only
    /// applies to SKUs assigned via expected machines.
    #[serde(default)]
    pub auto_generate_missing_sku: bool,
    /// The inteveral between attempting to generate a SKU from amachine
    #[serde(
        default = "BomValidationConfig::default_bom_validation_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub auto_generate_missing_sku_interval: std::time::Duration,
}

impl BomValidationConfig {
    const fn default_bom_validation_interval() -> std::time::Duration {
        std::time::Duration::from_secs(300)
    }
}
