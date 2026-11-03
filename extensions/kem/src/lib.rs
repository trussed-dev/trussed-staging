// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_std]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use trussed_core::{
    serde_extensions::{Extension, ExtensionClient, ExtensionResult},
    types::{KeyId, ShortData, StorageAttributes},
    Error,
};

pub struct KemExtension;

impl Extension for KemExtension {
    type Request = KemRequest;
    type Reply = KemReply;
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
pub enum KemRequest {
    Encapsulate(KemEncapsulateRequest),
    Decapsulate(KemDecapsulateRequest),
}
#[derive(Serialize, Deserialize)]
pub enum KemReply {
    Encapsulate(KemEncapsulateReply),
    Decapsulate(KemDecapsulateReply),
}

impl From<KemDecapsulateRequest> for KemRequest {
    fn from(v: KemDecapsulateRequest) -> Self {
        Self::Decapsulate(v)
    }
}

impl From<KemEncapsulateRequest> for KemRequest {
    fn from(v: KemEncapsulateRequest) -> Self {
        Self::Encapsulate(v)
    }
}

impl From<KemDecapsulateReply> for KemReply {
    fn from(v: KemDecapsulateReply) -> Self {
        Self::Decapsulate(v)
    }
}

impl From<KemEncapsulateReply> for KemReply {
    fn from(v: KemEncapsulateReply) -> Self {
        Self::Encapsulate(v)
    }
}

impl TryFrom<KemRequest> for KemDecapsulateRequest {
    type Error = Error;
    fn try_from(v: KemRequest) -> Result<Self, Error> {
        match v {
            KemRequest::Decapsulate(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}
impl TryFrom<KemRequest> for KemEncapsulateRequest {
    type Error = Error;
    fn try_from(v: KemRequest) -> Result<Self, Error> {
        match v {
            KemRequest::Encapsulate(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl TryFrom<KemReply> for KemDecapsulateReply {
    type Error = Error;
    fn try_from(v: KemReply) -> Result<Self, Error> {
        match v {
            KemReply::Decapsulate(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}
impl TryFrom<KemReply> for KemEncapsulateReply {
    type Error = Error;
    fn try_from(v: KemReply) -> Result<Self, Error> {
        match v {
            KemReply::Encapsulate(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct KemEncapsulateReply {
    pub ciphertext: ShortData,
    pub shared_secret: KeyId,
}

#[derive(Serialize, Deserialize)]
pub struct KemEncapsulateRequest {
    pub key: KeyId,
    pub attributes: StorageAttributes,
}

#[derive(Serialize, Deserialize)]
pub struct KemDecapsulateReply {
    pub key: KeyId,
}

#[derive(Serialize, Deserialize)]
pub struct KemDecapsulateRequest {
    pub key: KeyId,
    pub ciphertext: ShortData,
    pub attributes: StorageAttributes,
}

pub type KemResult<'a, R, C> = ExtensionResult<'a, KemExtension, R, C>;

pub trait KemClient: ExtensionClient<KemExtension> {
    fn kem_encapsulate(
        &mut self,
        key: KeyId,
        attributes: StorageAttributes,
    ) -> KemResult<'_, KemEncapsulateReply, Self> {
        self.extension(KemRequest::Encapsulate(KemEncapsulateRequest {
            key,
            attributes,
        }))
    }
    fn kem_decapsulate(
        &mut self,
        key: KeyId,
        ciphertext: ShortData,
        attributes: StorageAttributes,
    ) -> KemResult<'_, KemDecapsulateReply, Self> {
        self.extension(KemRequest::Decapsulate(KemDecapsulateRequest {
            key,
            ciphertext,
            attributes,
        }))
    }
}

impl<C: ExtensionClient<KemExtension>> KemClient for C {}
