// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use serde::{Deserialize, Serialize};
use trussed::{
    client::ClientError,
    config::MAX_SERIALIZED_KEY_LENGTH,
    key::{self, Kind, Secrecy},
    serde_extensions::{Extension, ExtensionClient, ExtensionImpl, ExtensionResult},
    service::{Filestore, Keystore, ServiceResources},
    types::{Bytes, CoreContext, GenericArray, KeyId, Location, Mechanism, PathBuf},
    Error,
};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const KIND: Kind = Kind::Symmetric(KEY_LEN);
const WRAPPED_TO_FILE_LEN: usize = MAX_SERIALIZED_KEY_LENGTH + NONCE_LEN + TAG_LEN;

#[derive(Debug, Default)]
pub struct WrapKeyToFileExtension;

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum WrapKeyToFileRequest {
    WrapKeyToFile(request::WrapKeyToFile),
    UnwrapKeyFromFile(request::UnwrapKeyFromFile),
}

mod request {
    use super::*;
    use serde::{Deserialize, Serialize};
    use trussed::types::{KeyId, Location, Mechanism, Message, PathBuf};
    use trussed::Error;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WrapKeyToFile {
        pub mechanism: Mechanism,
        pub wrapping_key: KeyId,
        pub key: KeyId,
        pub path: PathBuf,
        pub location: Location,
        pub associated_data: Message,
    }

    impl TryFrom<WrapKeyToFileRequest> for WrapKeyToFile {
        type Error = Error;
        fn try_from(request: WrapKeyToFileRequest) -> Result<Self, Self::Error> {
            match request {
                WrapKeyToFileRequest::WrapKeyToFile(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<WrapKeyToFile> for WrapKeyToFileRequest {
        fn from(request: WrapKeyToFile) -> Self {
            Self::WrapKeyToFile(request)
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct UnwrapKeyFromFile {
        pub mechanism: Mechanism,
        pub key: KeyId,
        pub path: PathBuf,
        pub file_location: Location,
        pub key_location: Location,
        pub associated_data: Message,
    }

    impl TryFrom<WrapKeyToFileRequest> for UnwrapKeyFromFile {
        type Error = Error;
        fn try_from(request: WrapKeyToFileRequest) -> Result<Self, Self::Error> {
            match request {
                WrapKeyToFileRequest::UnwrapKeyFromFile(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<UnwrapKeyFromFile> for WrapKeyToFileRequest {
        fn from(request: UnwrapKeyFromFile) -> Self {
            Self::UnwrapKeyFromFile(request)
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum WrapKeyToFileReply {
    WrapKeyToFile(reply::WrapKeyToFile),
    UnwrapKeyFromFile(reply::UnwrapKeyFromFile),
}

mod reply {
    use serde::{Deserialize, Serialize};
    use trussed::{types::KeyId, Error};

    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    #[non_exhaustive]
    pub struct WrapKeyToFile {}

    impl TryFrom<WrapKeyToFileReply> for WrapKeyToFile {
        type Error = Error;
        fn try_from(reply: WrapKeyToFileReply) -> Result<Self, Self::Error> {
            match reply {
                WrapKeyToFileReply::WrapKeyToFile(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<WrapKeyToFile> for WrapKeyToFileReply {
        fn from(reply: WrapKeyToFile) -> Self {
            Self::WrapKeyToFile(reply)
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct UnwrapKeyFromFile {
        pub key: Option<KeyId>,
    }

    impl TryFrom<WrapKeyToFileReply> for UnwrapKeyFromFile {
        type Error = Error;
        fn try_from(reply: WrapKeyToFileReply) -> Result<Self, Self::Error> {
            match reply {
                WrapKeyToFileReply::UnwrapKeyFromFile(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<UnwrapKeyFromFile> for WrapKeyToFileReply {
        fn from(reply: UnwrapKeyFromFile) -> Self {
            Self::UnwrapKeyFromFile(reply)
        }
    }
}

impl Extension for WrapKeyToFileExtension {
    type Request = WrapKeyToFileRequest;
    type Reply = WrapKeyToFileReply;
}

pub fn wrap_key_to_file(
    keystore: &mut impl Keystore,
    filestore: &mut impl Filestore,
    request: &request::WrapKeyToFile,
) -> Result<reply::WrapKeyToFile, Error> {
    if !matches!(
        request.mechanism,
        trussed::types::Mechanism::Chacha8Poly1305
    ) {
        return Err(Error::MechanismInvalid);
    }

    use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
    use chacha20poly1305::ChaCha8Poly1305;
    use rand_core::RngCore as _;

    let serialized_key = keystore.load_key(Secrecy::Secret, None, &request.key)?;

    let mut data = Bytes::<WRAPPED_TO_FILE_LEN>::from_slice(&serialized_key.serialize()).unwrap();
    let material_len = data.len();
    data.resize_default(material_len + NONCE_LEN).unwrap();
    let (material, nonce) = data.split_at_mut(material_len);
    keystore.rng().fill_bytes(nonce);
    let nonce = (&*nonce).try_into().unwrap();

    let key = keystore.load_key(Secrecy::Secret, Some(KIND), &request.wrapping_key)?;
    let chachakey: [u8; KEY_LEN] = (&*key.material).try_into().unwrap();
    let mut aead = ChaCha8Poly1305::new(&GenericArray::clone_from_slice(&chachakey));
    let tag = aead
        .encrypt_in_place_detached(
            <&GenericArray<_, _> as From<&[u8; NONCE_LEN]>>::from(nonce),
            &request.associated_data,
            material,
        )
        .unwrap();
    data.extend_from_slice(&tag).unwrap();
    filestore.write(&request.path, request.location, &data)?;
    Ok(reply::WrapKeyToFile {})
}

pub fn unwrap_key_from_file(
    keystore: &mut impl Keystore,
    filestore: &mut impl Filestore,
    request: &request::UnwrapKeyFromFile,
) -> Result<reply::UnwrapKeyFromFile, Error> {
    if !matches!(
        request.mechanism,
        trussed::types::Mechanism::Chacha8Poly1305
    ) {
        return Err(Error::MechanismInvalid);
    }

    use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
    use chacha20poly1305::ChaCha8Poly1305;
    let mut data: Bytes<WRAPPED_TO_FILE_LEN> =
        filestore.read(&request.path, request.file_location)?;

    let data_len = data.len();
    if data_len < TAG_LEN + NONCE_LEN {
        error!("Attempt to unwrap file that doesn't contain a key");
        return Err(Error::InvalidSerializedKey);
    }
    let (tmp, tag) = data.split_at_mut(data_len - TAG_LEN);
    let tmp_len = tmp.len();
    let (material, nonce) = tmp.split_at_mut(tmp_len - NONCE_LEN);

    // Coerce to array
    let nonce = (&*nonce).try_into().unwrap();
    let tag = (&*tag).try_into().unwrap();

    let key = keystore.load_key(key::Secrecy::Secret, Some(KIND), &request.key)?;
    let chachakey: [u8; KEY_LEN] = (&*key.material).try_into().unwrap();
    let mut aead = ChaCha8Poly1305::new(&GenericArray::clone_from_slice(&chachakey));
    if aead
        .decrypt_in_place_detached(
            <&GenericArray<_, _> as From<&[u8; NONCE_LEN]>>::from(nonce),
            &request.associated_data,
            material,
            <&GenericArray<_, _> as From<&[u8; TAG_LEN]>>::from(tag),
        )
        .is_err()
    {
        return Ok(reply::UnwrapKeyFromFile { key: None });
    }
    let key = key::Key::try_deserialize(material)?;
    let info = key::Info {
        flags: key.flags,
        kind: key.kind,
    };
    let key = keystore.store_key(request.key_location, Secrecy::Secret, info, &key.material)?;
    Ok(reply::UnwrapKeyFromFile { key: Some(key) })
}

impl ExtensionImpl<WrapKeyToFileExtension> for super::StagingBackend {
    fn extension_request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &WrapKeyToFileRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<WrapKeyToFileReply, Error> {
        let keystore = &mut resources.keystore(core_ctx)?;
        let filestore = &mut resources.filestore(core_ctx);
        match request {
            WrapKeyToFileRequest::WrapKeyToFile(request) => {
                wrap_key_to_file(keystore, filestore, request).map(Into::into)
            }
            WrapKeyToFileRequest::UnwrapKeyFromFile(request) => {
                unwrap_key_from_file(keystore, filestore, request).map(Into::into)
            }
        }
    }
}

type WrapKeyToFileResult<'a, R, C> = ExtensionResult<'a, WrapKeyToFileExtension, R, C>;

pub trait WrapKeyToFileClient: ExtensionClient<WrapKeyToFileExtension> {
    /// Wrap a key to a file
    /// This enables wrapping keys that don't fit in the buffers used by
    /// [`write_file`](trussed::client::FilesystemClient::write_file) and [`read_file`](trussed::client::FilesystemClient::read_file)
    fn wrap_key_to_file(
        &mut self,
        mechanism: Mechanism,
        wrapping_key: KeyId,
        key: KeyId,
        path: PathBuf,
        location: Location,
        associated_data: &[u8],
    ) -> WrapKeyToFileResult<'_, reply::WrapKeyToFile, Self> {
        let associated_data =
            Bytes::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        self.extension(request::WrapKeyToFile {
            mechanism,
            wrapping_key,
            key,
            path,
            location,
            associated_data,
        })
    }

    /// Wrap a key to a file
    /// This enables wrapping keys that don't fit in the buffers used by
    /// [`write_file`](trussed::client::FilesystemClient::write_file) and [`read_file`](trussed::client::FilesystemClient::read_file)
    fn unwrap_key_from_file(
        &mut self,
        mechanism: Mechanism,
        key: KeyId,
        path: PathBuf,
        file_location: Location,
        key_location: Location,
        associated_data: &[u8],
    ) -> WrapKeyToFileResult<'_, reply::UnwrapKeyFromFile, Self> {
        let associated_data =
            Bytes::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        self.extension(request::UnwrapKeyFromFile {
            mechanism,
            key,
            path,
            file_location,
            key_location,
            associated_data,
        })
    }
}

impl<C: ExtensionClient<WrapKeyToFileExtension>> WrapKeyToFileClient for C {}
