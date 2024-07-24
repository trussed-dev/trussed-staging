// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

#![no_std]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use trussed::{serde_extensions::Extension, types::Location, Error};

pub struct FsInfoExtension;

#[derive(Serialize, Deserialize)]
pub enum FsInfoExtensionRequest {
    FsInfo(FsInfoRequest),
}

#[derive(Serialize, Deserialize)]
pub struct FsInfoRequest {
    pub location: Location,
}

impl From<FsInfoRequest> for FsInfoExtensionRequest {
    fn from(value: FsInfoRequest) -> Self {
        Self::FsInfo(value)
    }
}

impl TryFrom<FsInfoExtensionRequest> for FsInfoRequest {
    type Error = Error;

    fn try_from(value: FsInfoExtensionRequest) -> Result<Self, Self::Error> {
        match value {
            FsInfoExtensionRequest::FsInfo(v) => Ok(v),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum FsInfoExtensionReply {
    FsInfo(FsInfoReply),
}

#[derive(Serialize, Deserialize)]
pub struct FsInfoReply {
    pub block_info: Option<BlockInfo>,
    pub available_space: usize,
}

#[derive(Serialize, Deserialize)]
pub struct BlockInfo {
    pub size: usize,
    pub total: usize,
    pub available: usize,
}

impl From<FsInfoReply> for FsInfoExtensionReply {
    fn from(value: FsInfoReply) -> Self {
        Self::FsInfo(value)
    }
}

impl TryFrom<FsInfoExtensionReply> for FsInfoReply {
    type Error = Error;

    fn try_from(value: FsInfoExtensionReply) -> Result<Self, Self::Error> {
        match value {
            FsInfoExtensionReply::FsInfo(v) => Ok(v),
        }
    }
}

impl Extension for FsInfoExtension {
    type Request = FsInfoExtensionRequest;
    type Reply = FsInfoExtensionReply;
}
