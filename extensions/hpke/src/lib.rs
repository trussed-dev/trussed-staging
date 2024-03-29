// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Trussed Extension providing DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
//! For more details, see https://www.rfc-editor.org/rfc/rfc9180.html#name-dhkemx25519-hkdf-sha256-hkdf

#![no_std]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;

use trussed::serde_extensions::{Extension, ExtensionClient, ExtensionResult};
use trussed::types::{KeyId, Location, Message, ShortData};
use trussed::Error;

#[derive(Deserialize, Serialize)]
pub enum HpkeRequest {
    Seal(HpkeSealRequest),
    Open(HpkeOpenRequest),
}

impl From<HpkeSealRequest> for HpkeRequest {
    fn from(value: HpkeSealRequest) -> Self {
        Self::Seal(value)
    }
}
impl From<HpkeOpenRequest> for HpkeRequest {
    fn from(value: HpkeOpenRequest) -> Self {
        Self::Open(value)
    }
}
impl TryFrom<HpkeRequest> for HpkeSealRequest {
    type Error = Error;
    fn try_from(value: HpkeRequest) -> Result<Self, Self::Error> {
        match value {
            HpkeRequest::Seal(this) => Ok(this),
            _ => Err(Error::InternalError),
        }
    }
}

impl TryFrom<HpkeRequest> for HpkeOpenRequest {
    type Error = Error;
    fn try_from(value: HpkeRequest) -> Result<Self, Self::Error> {
        match value {
            HpkeRequest::Open(this) => Ok(this),
            _ => Err(Error::InternalError),
        }
    }
}

/// Seal to a public key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeSealRequest {
    pub key: KeyId,
    pub plaintext: Message,
    pub aad: ShortData,
    pub info: ShortData,
    /// The location of the stored "enc" key
    pub enc_location: Location,
}

/// Open with a private key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeOpenRequest {
    pub key: KeyId,
    pub enc_key: KeyId,
    pub ciphertext: Message,
    pub tag: ByteArray<16>,
    pub aad: ShortData,
    pub info: ShortData,
}

#[derive(Deserialize, Serialize)]
pub enum HpkeReply {
    Seal(HpkeSealReply),
    Open(HpkeOpenReply),
}

impl From<HpkeSealReply> for HpkeReply {
    fn from(value: HpkeSealReply) -> Self {
        Self::Seal(value)
    }
}
impl From<HpkeOpenReply> for HpkeReply {
    fn from(value: HpkeOpenReply) -> Self {
        Self::Open(value)
    }
}
impl TryFrom<HpkeReply> for HpkeSealReply {
    type Error = Error;
    fn try_from(value: HpkeReply) -> Result<Self, Self::Error> {
        match value {
            HpkeReply::Seal(this) => Ok(this),
            _ => Err(Error::InternalError),
        }
    }
}

impl TryFrom<HpkeReply> for HpkeOpenReply {
    type Error = Error;
    fn try_from(value: HpkeReply) -> Result<Self, Self::Error> {
        match value {
            HpkeReply::Open(this) => Ok(this),
            _ => Err(Error::InternalError),
        }
    }
}

/// Seal to a public key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeSealReply {
    pub enc: KeyId,
    pub ciphertext: Message,
    pub tag: ByteArray<16>,
}

/// Open with a private key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeOpenReply {
    pub plaintext: Message,
}

pub type HpkeResult<'a, R, C> = ExtensionResult<'a, HpkeExtension, R, C>;

pub struct HpkeExtension;

impl Extension for HpkeExtension {
    type Request = HpkeRequest;
    type Reply = HpkeReply;
}

pub trait HpkeClient: ExtensionClient<HpkeExtension> {
    fn hpke_seal(
        &mut self,
        key: KeyId,
        plaintext: Message,
        aad: ShortData,
        info: ShortData,
        enc_location: Location,
    ) -> HpkeResult<'_, HpkeSealReply, Self> {
        self.extension(HpkeRequest::Seal(HpkeSealRequest {
            key,
            plaintext,
            aad,
            info,
            enc_location,
        }))
    }

    fn hpke_open(
        &mut self,
        key: KeyId,
        enc_key: KeyId,
        ciphertext: Message,
        tag: ByteArray<16>,
        aad: ShortData,
        info: ShortData,
    ) -> HpkeResult<'_, HpkeOpenReply, Self> {
        self.extension(HpkeRequest::Open(HpkeOpenRequest {
            key,
            tag,
            enc_key,
            ciphertext,
            aad,
            info,
        }))
    }
}

impl<T: ExtensionClient<HpkeExtension>> HpkeClient for T {}
