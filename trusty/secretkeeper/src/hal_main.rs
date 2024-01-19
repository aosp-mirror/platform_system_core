//
// Copyright (C) 2022 The Android Open-Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module implements the HAL service for Secretkeeper in Trusty.
use authgraph_hal::{channel::SerializedChannel};
use secretkeeper_hal::SecretkeeperService;
use android_hardware_security_secretkeeper::aidl::android::hardware::security::secretkeeper::ISecretkeeper::{
    ISecretkeeper, BpSecretkeeper,
};
use log::{error, info};
use std::{
    ffi::CString,
    panic,
    sync::{Arc, Mutex},
};
use trusty::DEFAULT_DEVICE;

const SK_TIPC_SERVICE_PORT: &str = "com.android.trusty.secretkeeper";
const AG_TIPC_SERVICE_PORT: &str = "com.android.trusty.secretkeeper.authgraph";

static SERVICE_INSTANCE: &str = "default";

/// Local error type for failures in the HAL service.
#[derive(Debug, Clone)]
struct HalServiceError(String);

#[derive(Debug)]
struct TipcChannel {
    channel: Arc<Mutex<trusty::TipcChannel>>,
}

impl TipcChannel {
    fn new(channel: trusty::TipcChannel) -> Self {
        Self { channel: Arc::new(Mutex::new(channel)) }
    }
}

impl SerializedChannel for TipcChannel {
    const MAX_SIZE: usize = 4000;
    fn execute(&self, req_data: &[u8]) -> binder::Result<Vec<u8>> {
        // Hold lock across both request and response.
        let mut channel = self.channel.lock().unwrap();
        channel.send(req_data).map_err(|e| {
            binder::Status::new_exception(
                binder::ExceptionCode::TRANSACTION_FAILED,
                Some(
                    &CString::new(format!(
                        "Failed to send the request via tipc channel because of {:?}",
                        e
                    ))
                    .unwrap(),
                ),
            )
        })?;
        // TODO: cope with fragmentation and reassembly
        let mut rsp_data = Vec::new();
        channel.recv(&mut rsp_data).map_err(|e| {
            binder::Status::new_exception(
                binder::ExceptionCode::TRANSACTION_FAILED,
                Some(
                    &CString::new(format!(
                        "Failed to receive the response via tipc channel because of {:?}",
                        e
                    ))
                    .unwrap(),
                ),
            )
        })?;
        Ok(rsp_data)
    }
}

fn main() {
    if let Err(e) = inner_main() {
        panic!("HAL service failed: {:?}", e);
    }
}

fn inner_main() -> Result<(), HalServiceError> {
    // Initialize Android logging.
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("secretkeeper-hal-trusty")
            .with_min_level(log::Level::Info)
            .with_log_id(android_logger::LogId::System),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    info!("Trusty Secretkeeper HAL service is starting.");

    info!("Starting thread pool now.");
    binder::ProcessState::start_thread_pool();

    // Create connections to the TA.
    let ag_connection = trusty::TipcChannel::connect(DEFAULT_DEVICE, AG_TIPC_SERVICE_PORT)
        .map_err(|e| {
            HalServiceError(format!(
                "Failed to connect to Trusty port {AG_TIPC_SERVICE_PORT} because of {:?}.",
                e
            ))
        })?;
    let ag_tipc_channel = TipcChannel::new(ag_connection);

    let sk_connection = trusty::TipcChannel::connect(DEFAULT_DEVICE, SK_TIPC_SERVICE_PORT)
        .map_err(|e| {
            HalServiceError(format!(
                "Failed to connect to Trusty port {SK_TIPC_SERVICE_PORT} because of {:?}.",
                e
            ))
        })?;
    let sk_tipc_channel = TipcChannel::new(sk_connection);

    // Register the AIDL service
    let service = SecretkeeperService::new_as_binder(sk_tipc_channel, ag_tipc_channel);
    let service_name =
        format!("{}/{}", <BpSecretkeeper as ISecretkeeper>::get_descriptor(), SERVICE_INSTANCE);
    binder::add_service(&service_name, service.as_binder()).map_err(|e| {
        HalServiceError(format!("Failed to register service {} because of {:?}.", service_name, e))
    })?;

    info!("Successfully registered Secretkeeper HAL service.");
    info!("Joining thread pool now.");
    binder::ProcessState::join_thread_pool();
    info!("Secretkeeper HAL service is terminating."); // should not reach here
    Ok(())
}
