// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_std]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use trussed::{
    error::Error,
    serde_extensions::{Extension, ExtensionClient, ExtensionResult},
    types::{Path, PathBuf},
};

pub struct ManageExtension;

/// Factory reset the entire device
///
/// This will reset all filesystems
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct FactoryResetDeviceRequest;

/// Factory reset a specific application
///
/// This will reset all data for a specific client
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FactoryResetClientRequest {
    pub client: PathBuf,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum ManageRequest {
    FactoryResetDevice(FactoryResetDeviceRequest),
    FactoryResetClient(FactoryResetClientRequest),
}

impl From<FactoryResetClientRequest> for ManageRequest {
    fn from(value: FactoryResetClientRequest) -> Self {
        Self::FactoryResetClient(value)
    }
}

impl TryFrom<ManageRequest> for FactoryResetClientRequest {
    type Error = Error;
    fn try_from(value: ManageRequest) -> Result<Self, Self::Error> {
        match value {
            ManageRequest::FactoryResetClient(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<FactoryResetDeviceRequest> for ManageRequest {
    fn from(value: FactoryResetDeviceRequest) -> Self {
        Self::FactoryResetDevice(value)
    }
}

impl TryFrom<ManageRequest> for FactoryResetDeviceRequest {
    type Error = Error;
    fn try_from(value: ManageRequest) -> Result<Self, Self::Error> {
        match value {
            ManageRequest::FactoryResetDevice(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

/// Factory reset the entire device
///
/// This will reset all filesystems
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct FactoryResetDeviceReply;

/// Factory reset a specific application
///
/// This will reset all data for a specific client
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FactoryResetClientReply;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum ManageReply {
    FactoryResetDevice(FactoryResetDeviceReply),
    FactoryResetClient(FactoryResetClientReply),
}

impl From<FactoryResetClientReply> for ManageReply {
    fn from(value: FactoryResetClientReply) -> Self {
        Self::FactoryResetClient(value)
    }
}

impl TryFrom<ManageReply> for FactoryResetClientReply {
    type Error = Error;
    fn try_from(value: ManageReply) -> Result<Self, Self::Error> {
        match value {
            ManageReply::FactoryResetClient(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<FactoryResetDeviceReply> for ManageReply {
    fn from(value: FactoryResetDeviceReply) -> Self {
        Self::FactoryResetDevice(value)
    }
}

impl TryFrom<ManageReply> for FactoryResetDeviceReply {
    type Error = Error;
    fn try_from(value: ManageReply) -> Result<Self, Self::Error> {
        match value {
            ManageReply::FactoryResetDevice(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl Extension for ManageExtension {
    type Request = ManageRequest;
    type Reply = ManageReply;
}

pub type ManageResult<'a, R, C> = ExtensionResult<'a, ManageExtension, R, C>;

pub trait ManageClient: ExtensionClient<ManageExtension> {
    /// Factory reset the entire device
    ///
    /// This will reset all filesystems
    fn factory_reset_device(&mut self) -> ManageResult<'_, FactoryResetDeviceReply, Self> {
        self.extension(FactoryResetDeviceRequest)
    }

    /// Factory reset the entire client
    ///
    fn factory_reset_client(
        &mut self,
        client: &Path,
    ) -> ManageResult<'_, FactoryResetClientReply, Self> {
        self.extension(FactoryResetClientRequest {
            client: client.into(),
        })
    }
}

impl<C: ExtensionClient<ManageExtension>> ManageClient for C {}
