// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_std]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use trussed::{
    client::ClientError,
    serde_extensions::{Extension, ExtensionClient, ExtensionResult},
    types::{Bytes, KeyId, Location, Mechanism, PathBuf},
};

#[derive(Debug, Default)]
pub struct WrapKeyToFileExtension;

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum WrapKeyToFileRequest {
    WrapKeyToFile(request::WrapKeyToFile),
    UnwrapKeyFromFile(request::UnwrapKeyFromFile),
}

pub mod request {
    use super::*;
    use serde::{Deserialize, Serialize};
    use trussed::error::Error;
    use trussed::types::{KeyId, Location, Mechanism, Message, PathBuf};

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

pub mod reply {
    use serde::{Deserialize, Serialize};
    use trussed::{types::KeyId, error::Error};

    use super::*;

    #[derive(Debug, Deserialize, Serialize, Default)]
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

pub type WrapKeyToFileResult<'a, R, C> = ExtensionResult<'a, WrapKeyToFileExtension, R, C>;

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
