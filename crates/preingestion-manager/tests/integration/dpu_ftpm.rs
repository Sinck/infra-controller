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

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use carbide_preingestion_manager::PreingestionManager;
use carbide_redfish::libredfish::test_support::{RedfishSim, RedfishSimAction};
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::default_config;
use carbide_test_harness::test_support::fixture_config::FixtureDefault;
use libredfish::SystemPowerControl;
use model::site_explorer::PreingestionState;
use model::test_support::DpuConfig;
use rpc::forge::DhcpDiscovery;
use serde_json::Value;

#[sqlx_test]
async fn initial_dpu_ingestion_enables_ftpm_and_restarts_the_dpu(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = TestHarness::builder(pool.clone()).build().await;
    let domain = env.test_domain().await;
    let underlay_segment = env
        .network_controller()
        .create_underlay_segment(&domain)
        .await;
    let config = default_config::get();
    let redfish_sim = Arc::new(RedfishSim::default());
    let manager = PreingestionManager::new(
        pool.clone(),
        config.preingestion_manager(),
        redfish_sim.clone(),
        env.test_meter.meter(),
        None,
        None,
        None,
        env.api().work_lock_manager_handle(),
        config.ntp_servers.clone(),
    );

    let address = env
        .api()
        .discover_dhcp(
            DhcpDiscovery::builder("b8:3f:d2:90:97:a6", underlay_segment.relay_address)
                .vendor_string("Bluefield")
                .tonic_request(),
        )
        .await?
        .into_inner()
        .address;
    let ip_address = IpAddr::from_str(&address)?;
    let dpu_report = DpuConfig::default().into();
    let mut transaction = pool.begin().await?;
    db::explored_endpoints::insert(ip_address, &dpu_report, false, &mut transaction).await?;
    transaction.commit().await?;

    redfish_sim.set_bios_attributes(
        &address,
        HashMap::from([("EnableOPTEE".to_string(), Value::Bool(false))]),
    );
    let timepoint = redfish_sim.timepoint();

    manager.run_single_iteration().await?;

    assert_eq!(
        redfish_sim.bios_attributes(&address).get("EnableOPTEE"),
        Some(&Value::Bool(true)),
        "initial DPU ingestion should enable the OP-TEE fTPM prerequisite"
    );
    assert!(
        redfish_sim
            .actions_since(&timepoint)
            .for_host(&address)
            .contains(&RedfishSimAction::Power(SystemPowerControl::ForceRestart)),
        "initial DPU ingestion should restart the DPU to apply the BIOS setting"
    );

    let mut transaction = pool.begin().await?;
    let endpoint = db::explored_endpoints::find_all_by_ip(ip_address, &mut transaction)
        .await?
        .into_iter()
        .next()
        .expect("DPU endpoint should exist");
    transaction.commit().await?;
    assert!(
        matches!(
            endpoint.preingestion_state,
            PreingestionState::InitialBMCReset { .. }
        ),
        "fTPM setup should proceed through the remaining preingestion flow; got {:?}",
        endpoint.preingestion_state
    );

    Ok(())
}
