// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Trussed Extension providing DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
//! For more details, see <https://www.rfc-editor.org/rfc/rfc9180.html#name-dhkemx25519-hkdf-sha256-hkdf>

#![no_std]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;

use trussed_core::serde_extensions::{Extension, ExtensionClient, ExtensionResult};
use trussed_core::types::{KeyId, Location, Message, PathBuf, ShortData};
use trussed_core::Error;

#[derive(Deserialize, Serialize)]
pub enum HpkeRequest {
    Seal(HpkeSealRequest),
    SealKey(HpkeSealKeyRequest),
    SealKeyToFile(HpkeSealKeyToFileRequest),
    Open(HpkeOpenRequest),
    OpenKey(HpkeOpenKeyRequest),
    OpenKeyFromFile(HpkeOpenKeyFromFileRequest),
}

impl From<HpkeSealRequest> for HpkeRequest {
    fn from(value: HpkeSealRequest) -> Self {
        Self::Seal(value)
    }
}
impl From<HpkeSealKeyRequest> for HpkeRequest {
    fn from(value: HpkeSealKeyRequest) -> Self {
        Self::SealKey(value)
    }
}
impl From<HpkeSealKeyToFileRequest> for HpkeRequest {
    fn from(value: HpkeSealKeyToFileRequest) -> Self {
        Self::SealKeyToFile(value)
    }
}
impl From<HpkeOpenRequest> for HpkeRequest {
    fn from(value: HpkeOpenRequest) -> Self {
        Self::Open(value)
    }
}
impl From<HpkeOpenKeyRequest> for HpkeRequest {
    fn from(value: HpkeOpenKeyRequest) -> Self {
        Self::OpenKey(value)
    }
}
impl From<HpkeOpenKeyFromFileRequest> for HpkeRequest {
    fn from(value: HpkeOpenKeyFromFileRequest) -> Self {
        Self::OpenKeyFromFile(value)
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

impl TryFrom<HpkeRequest> for HpkeSealKeyRequest {
    type Error = Error;
    fn try_from(value: HpkeRequest) -> Result<Self, Self::Error> {
        match value {
            HpkeRequest::SealKey(this) => Ok(this),
            _ => Err(Error::InternalError),
        }
    }
}

impl TryFrom<HpkeRequest> for HpkeSealKeyToFileRequest {
    type Error = Error;
    fn try_from(value: HpkeRequest) -> Result<Self, Self::Error> {
        match value {
            HpkeRequest::SealKeyToFile(this) => Ok(this),
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

impl TryFrom<HpkeRequest> for HpkeOpenKeyRequest {
    type Error = Error;
    fn try_from(value: HpkeRequest) -> Result<Self, Self::Error> {
        match value {
            HpkeRequest::OpenKey(this) => Ok(this),
            _ => Err(Error::InternalError),
        }
    }
}

impl TryFrom<HpkeRequest> for HpkeOpenKeyFromFileRequest {
    type Error = Error;
    fn try_from(value: HpkeRequest) -> Result<Self, Self::Error> {
        match value {
            HpkeRequest::OpenKeyFromFile(this) => Ok(this),
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

/// Seal to a public key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeSealKeyRequest {
    pub public_key: KeyId,
    pub key_to_seal: KeyId,
    pub aad: ShortData,
    pub info: ShortData,
}

/// Seal to a public key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeSealKeyToFileRequest {
    pub public_key: KeyId,
    pub key_to_seal: KeyId,
    pub aad: ShortData,
    pub info: ShortData,
    pub file: PathBuf,
    pub location: Location,
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

/// Open with a private key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeOpenKeyRequest {
    pub key: KeyId,
    pub sealed_key: Message,
    pub aad: ShortData,
    pub info: ShortData,
    pub location: Location,
}

/// Open with a private key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeOpenKeyFromFileRequest {
    pub key: KeyId,
    pub sealed_key: PathBuf,
    pub sealed_location: Location,
    pub unsealed_location: Location,
    pub aad: ShortData,
    pub info: ShortData,
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
/// Seal a key to a public key
#[derive(Deserialize, Serialize)]
pub struct HpkeSealKeyReply {
    pub data: Message,
}

/// Seal a key to a public key
#[derive(Deserialize, Serialize)]
pub struct HpkeSealKeyToFileReply {}

#[derive(Deserialize, Serialize)]
pub enum HpkeReply {
    Seal(HpkeSealReply),
    SealKey(HpkeSealKeyReply),
    SealKeyToFile(HpkeSealKeyToFileReply),
    Open(HpkeOpenReply),
    OpenKey(HpkeOpenKeyReply),
    OpenKeyFromFile(HpkeOpenKeyFromFileReply),
}

impl From<HpkeSealReply> for HpkeReply {
    fn from(value: HpkeSealReply) -> Self {
        Self::Seal(value)
    }
}
impl From<HpkeSealKeyReply> for HpkeReply {
    fn from(value: HpkeSealKeyReply) -> Self {
        Self::SealKey(value)
    }
}
impl From<HpkeSealKeyToFileReply> for HpkeReply {
    fn from(value: HpkeSealKeyToFileReply) -> Self {
        Self::SealKeyToFile(value)
    }
}
impl From<HpkeOpenReply> for HpkeReply {
    fn from(value: HpkeOpenReply) -> Self {
        Self::Open(value)
    }
}
impl From<HpkeOpenKeyReply> for HpkeReply {
    fn from(value: HpkeOpenKeyReply) -> Self {
        Self::OpenKey(value)
    }
}
impl From<HpkeOpenKeyFromFileReply> for HpkeReply {
    fn from(value: HpkeOpenKeyFromFileReply) -> Self {
        Self::OpenKeyFromFile(value)
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

impl TryFrom<HpkeReply> for HpkeSealKeyReply {
    type Error = Error;
    fn try_from(value: HpkeReply) -> Result<Self, Self::Error> {
        match value {
            HpkeReply::SealKey(this) => Ok(this),
            _ => Err(Error::InternalError),
        }
    }
}

impl TryFrom<HpkeReply> for HpkeSealKeyToFileReply {
    type Error = Error;
    fn try_from(value: HpkeReply) -> Result<Self, Self::Error> {
        match value {
            HpkeReply::SealKeyToFile(this) => Ok(this),
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

impl TryFrom<HpkeReply> for HpkeOpenKeyReply {
    type Error = Error;
    fn try_from(value: HpkeReply) -> Result<Self, Self::Error> {
        match value {
            HpkeReply::OpenKey(this) => Ok(this),
            _ => Err(Error::InternalError),
        }
    }
}

impl TryFrom<HpkeReply> for HpkeOpenKeyFromFileReply {
    type Error = Error;
    fn try_from(value: HpkeReply) -> Result<Self, Self::Error> {
        match value {
            HpkeReply::OpenKeyFromFile(this) => Ok(this),
            _ => Err(Error::InternalError),
        }
    }
}

/// Open with a private key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeOpenReply {
    pub plaintext: Message,
}

/// Open with a private key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeOpenKeyReply {
    pub key: KeyId,
}

/// Open with a private key
///
/// As described in 6.1 with mode "base"
#[derive(Deserialize, Serialize)]
pub struct HpkeOpenKeyFromFileReply {
    pub key: KeyId,
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

    fn hpke_seal_key(
        &mut self,
        public_key: KeyId,
        key_to_seal: KeyId,
        aad: ShortData,
        info: ShortData,
    ) -> HpkeResult<'_, HpkeSealKeyReply, Self> {
        self.extension(HpkeRequest::SealKey(HpkeSealKeyRequest {
            public_key,
            key_to_seal,
            aad,
            info,
        }))
    }

    fn hpke_seal_key_to_file(
        &mut self,
        file: PathBuf,
        location: Location,
        public_key: KeyId,
        key_to_seal: KeyId,
        aad: ShortData,
        info: ShortData,
    ) -> HpkeResult<'_, HpkeSealKeyToFileReply, Self> {
        self.extension(HpkeRequest::SealKeyToFile(HpkeSealKeyToFileRequest {
            file,
            public_key,
            key_to_seal,
            aad,
            info,
            location,
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
    fn hpke_open_key(
        &mut self,
        key: KeyId,
        sealed_key: Message,
        aad: ShortData,
        info: ShortData,
        location: Location,
    ) -> HpkeResult<'_, HpkeOpenKeyReply, Self> {
        self.extension(HpkeRequest::OpenKey(HpkeOpenKeyRequest {
            key,
            sealed_key,
            aad,
            info,
            location,
        }))
    }
    fn hpke_open_key_from_file(
        &mut self,
        key: KeyId,
        sealed_key: PathBuf,
        sealed_location: Location,
        unsealed_location: Location,
        aad: ShortData,
        info: ShortData,
    ) -> HpkeResult<'_, HpkeOpenKeyFromFileReply, Self> {
        self.extension(HpkeRequest::OpenKeyFromFile(HpkeOpenKeyFromFileRequest {
            key,
            aad,
            info,
            sealed_key,
            sealed_location,
            unsealed_location,
        }))
    }
}

impl<T: ExtensionClient<HpkeExtension>> HpkeClient for T {}
