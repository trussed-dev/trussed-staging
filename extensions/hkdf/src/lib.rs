// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_std]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use trussed::{
    config::MAX_MEDIUM_DATA_LENGTH,
    error::Error,
    serde_extensions::{Extension, ExtensionClient, ExtensionResult},
    types::{Bytes, KeyId, Location, Message},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct OkmId(pub KeyId);

/// Can represent either data or a key
#[derive(Serialize, Deserialize)]
pub enum KeyOrData<const N: usize> {
    Key(KeyId),
    Data(Bytes<N>),
}

pub struct HkdfExtension;

impl Extension for HkdfExtension {
    type Request = HkdfRequest;
    type Reply = HkdfReply;
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
pub enum HkdfRequest {
    Extract(HkdfExtractRequest),
    Expand(HkdfExpandRequest),
}
#[derive(Serialize, Deserialize)]
pub enum HkdfReply {
    Extract(HkdfExtractReply),
    Expand(HkdfExpandReply),
}

impl From<HkdfExpandRequest> for HkdfRequest {
    fn from(v: HkdfExpandRequest) -> Self {
        Self::Expand(v)
    }
}

impl From<HkdfExtractRequest> for HkdfRequest {
    fn from(v: HkdfExtractRequest) -> Self {
        Self::Extract(v)
    }
}

impl From<HkdfExpandReply> for HkdfReply {
    fn from(v: HkdfExpandReply) -> Self {
        Self::Expand(v)
    }
}

impl From<HkdfExtractReply> for HkdfReply {
    fn from(v: HkdfExtractReply) -> Self {
        Self::Extract(v)
    }
}

impl TryFrom<HkdfRequest> for HkdfExpandRequest {
    type Error = Error;
    fn try_from(v: HkdfRequest) -> Result<Self, Error> {
        match v {
            HkdfRequest::Expand(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}
impl TryFrom<HkdfRequest> for HkdfExtractRequest {
    type Error = Error;
    fn try_from(v: HkdfRequest) -> Result<Self, Error> {
        match v {
            HkdfRequest::Extract(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl TryFrom<HkdfReply> for HkdfExpandReply {
    type Error = Error;
    fn try_from(v: HkdfReply) -> Result<Self, Error> {
        match v {
            HkdfReply::Expand(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}
impl TryFrom<HkdfReply> for HkdfExtractReply {
    type Error = Error;
    fn try_from(v: HkdfReply) -> Result<Self, Error> {
        match v {
            HkdfReply::Extract(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct HkdfExtractReply {
    pub okm: OkmId,
}

#[derive(Serialize, Deserialize)]
pub struct HkdfExtractRequest {
    pub ikm: KeyOrData<MAX_MEDIUM_DATA_LENGTH>,
    pub salt: Option<KeyOrData<MAX_MEDIUM_DATA_LENGTH>>,
    /// Location to store the OKM
    pub storage: Location,
}

#[derive(Serialize, Deserialize)]
pub struct HkdfExpandReply {
    pub key: KeyId,
}

#[derive(Serialize, Deserialize)]
pub struct HkdfExpandRequest {
    pub prk: OkmId,
    pub info: Message,
    pub len: usize,
    pub storage: Location,
}

pub type HkdfResult<'a, R, C> = ExtensionResult<'a, HkdfExtension, R, C>;

pub trait HkdfClient: ExtensionClient<HkdfExtension> {
    fn hkdf_extract(
        &mut self,
        ikm: KeyOrData<MAX_MEDIUM_DATA_LENGTH>,
        salt: Option<KeyOrData<MAX_MEDIUM_DATA_LENGTH>>,
        storage: Location,
    ) -> HkdfResult<'_, HkdfExtractReply, Self> {
        self.extension(HkdfRequest::Extract(HkdfExtractRequest {
            ikm,
            salt,
            storage,
        }))
    }
    fn hkdf_expand(
        &mut self,
        prk: OkmId,
        info: Message,
        len: usize,
        storage: Location,
    ) -> HkdfResult<'_, HkdfExpandReply, Self> {
        self.extension(HkdfRequest::Expand(HkdfExpandRequest {
            prk,
            info,
            len,
            storage,
        }))
    }
}

impl<C: ExtensionClient<HkdfExtension>> HkdfClient for C {}
