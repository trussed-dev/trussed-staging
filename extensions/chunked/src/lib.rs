// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![no_std]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

pub mod utils;

use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use trussed::{
    client::FilesystemClient,
    serde_extensions::{Extension, ExtensionClient, ExtensionResult},
    types::{KeyId, Location, Message, PathBuf, UserAttribute},
};

pub const CHACHA8_STREAM_NONCE_LEN: usize = 8;

#[derive(Debug, Default)]
pub struct ChunkedExtension;

impl Extension for ChunkedExtension {
    type Request = ChunkedRequest;
    type Reply = ChunkedReply;
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[allow(missing_docs, clippy::large_enum_variant)]
pub enum ChunkedRequest {
    StartChunkedWrite(request::StartChunkedWrite),
    StartEncryptedChunkedWrite(request::StartEncryptedChunkedWrite),
    StartChunkedRead(request::StartChunkedRead),
    StartEncryptedChunkedRead(request::StartEncryptedChunkedRead),
    ReadChunk(request::ReadChunk),
    WriteChunk(request::WriteChunk),
    AbortChunkedWrite(request::AbortChunkedWrite),
    PartialReadFile(request::PartialReadFile),
    AppendFile(request::AppendFile),
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum ChunkedReply {
    ReadChunk(reply::ReadChunk),
    StartChunkedWrite(reply::StartChunkedWrite),
    StartEncryptedChunkedWrite(reply::StartEncryptedChunkedWrite),
    StartChunkedRead(reply::StartChunkedRead),
    StartEncryptedChunkedRead(reply::StartEncryptedChunkedRead),
    WriteChunk(reply::WriteChunk),
    AbortChunkedWrite(reply::AbortChunkedWrite),
    PartialReadFile(reply::PartialReadFile),
    AppendFile(reply::AppendFile),
}

pub mod request {
    use super::*;
    use serde::{Deserialize, Serialize};
    use serde_byte_array::ByteArray;
    use trussed::error::Error;
    use trussed::types::{KeyId, Location, Message, PathBuf, UserAttribute};

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct ReadChunk {}

    impl TryFrom<ChunkedRequest> for ReadChunk {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::ReadChunk(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<ReadChunk> for ChunkedRequest {
        fn from(request: ReadChunk) -> Self {
            Self::ReadChunk(request)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartChunkedWrite {
        pub location: Location,
        pub path: PathBuf,
        pub user_attribute: Option<UserAttribute>,
    }

    impl TryFrom<ChunkedRequest> for StartChunkedWrite {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::StartChunkedWrite(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<StartChunkedWrite> for ChunkedRequest {
        fn from(request: StartChunkedWrite) -> Self {
            Self::StartChunkedWrite(request)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartEncryptedChunkedWrite {
        pub location: Location,
        pub path: PathBuf,
        pub user_attribute: Option<UserAttribute>,
        pub key: KeyId,
        pub nonce: Option<ByteArray<CHACHA8_STREAM_NONCE_LEN>>,
    }

    impl TryFrom<ChunkedRequest> for StartEncryptedChunkedWrite {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::StartEncryptedChunkedWrite(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<StartEncryptedChunkedWrite> for ChunkedRequest {
        fn from(request: StartEncryptedChunkedWrite) -> Self {
            Self::StartEncryptedChunkedWrite(request)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartChunkedRead {
        pub location: Location,
        pub path: PathBuf,
    }

    impl TryFrom<ChunkedRequest> for StartChunkedRead {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::StartChunkedRead(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<StartChunkedRead> for ChunkedRequest {
        fn from(request: StartChunkedRead) -> Self {
            Self::StartChunkedRead(request)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartEncryptedChunkedRead {
        pub location: Location,
        pub path: PathBuf,
        pub key: KeyId,
    }

    impl TryFrom<ChunkedRequest> for StartEncryptedChunkedRead {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::StartEncryptedChunkedRead(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<StartEncryptedChunkedRead> for ChunkedRequest {
        fn from(request: StartEncryptedChunkedRead) -> Self {
            Self::StartEncryptedChunkedRead(request)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct WriteChunk {
        pub data: Message,
    }

    impl TryFrom<ChunkedRequest> for WriteChunk {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::WriteChunk(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<WriteChunk> for ChunkedRequest {
        fn from(request: WriteChunk) -> Self {
            Self::WriteChunk(request)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct AbortChunkedWrite {}

    impl TryFrom<ChunkedRequest> for AbortChunkedWrite {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::AbortChunkedWrite(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<AbortChunkedWrite> for ChunkedRequest {
        fn from(request: AbortChunkedWrite) -> Self {
            Self::AbortChunkedWrite(request)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct PartialReadFile {
        pub location: Location,
        pub path: PathBuf,
        pub offset: usize,
        pub length: usize,
    }

    impl TryFrom<ChunkedRequest> for PartialReadFile {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::PartialReadFile(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<PartialReadFile> for ChunkedRequest {
        fn from(request: PartialReadFile) -> Self {
            Self::PartialReadFile(request)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct AppendFile {
        pub location: Location,
        pub path: PathBuf,
        pub data: Message,
    }

    impl TryFrom<ChunkedRequest> for AppendFile {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::AppendFile(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<AppendFile> for ChunkedRequest {
        fn from(request: AppendFile) -> Self {
            Self::AppendFile(request)
        }
    }
}

pub mod reply {
    use super::*;
    use serde::{Deserialize, Serialize};
    use trussed::error::Error;
    use trussed::types::Message;

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct ReadChunk {
        pub data: Message,
        pub len: usize,
    }

    impl TryFrom<ChunkedReply> for ReadChunk {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::ReadChunk(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<ReadChunk> for ChunkedReply {
        fn from(reply: ReadChunk) -> Self {
            Self::ReadChunk(reply)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartChunkedWrite {}

    impl TryFrom<ChunkedReply> for StartChunkedWrite {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::StartChunkedWrite(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<StartChunkedWrite> for ChunkedReply {
        fn from(reply: StartChunkedWrite) -> Self {
            Self::StartChunkedWrite(reply)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartEncryptedChunkedWrite {}

    impl TryFrom<ChunkedReply> for StartEncryptedChunkedWrite {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::StartEncryptedChunkedWrite(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<StartEncryptedChunkedWrite> for ChunkedReply {
        fn from(reply: StartEncryptedChunkedWrite) -> Self {
            Self::StartEncryptedChunkedWrite(reply)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartChunkedRead {
        pub data: Message,
        pub len: usize,
    }

    impl TryFrom<ChunkedReply> for StartChunkedRead {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::StartChunkedRead(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<StartChunkedRead> for ChunkedReply {
        fn from(reply: StartChunkedRead) -> Self {
            Self::StartChunkedRead(reply)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartEncryptedChunkedRead {}

    impl TryFrom<ChunkedReply> for StartEncryptedChunkedRead {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::StartEncryptedChunkedRead(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<StartEncryptedChunkedRead> for ChunkedReply {
        fn from(reply: StartEncryptedChunkedRead) -> Self {
            Self::StartEncryptedChunkedRead(reply)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct WriteChunk {}

    impl TryFrom<ChunkedReply> for WriteChunk {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::WriteChunk(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<WriteChunk> for ChunkedReply {
        fn from(reply: WriteChunk) -> Self {
            Self::WriteChunk(reply)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct AbortChunkedWrite {
        pub aborted: bool,
    }

    impl TryFrom<ChunkedReply> for AbortChunkedWrite {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::AbortChunkedWrite(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<AbortChunkedWrite> for ChunkedReply {
        fn from(reply: AbortChunkedWrite) -> Self {
            Self::AbortChunkedWrite(reply)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct PartialReadFile {
        pub data: Message,
        pub file_length: usize,
    }

    impl TryFrom<ChunkedReply> for PartialReadFile {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::PartialReadFile(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<PartialReadFile> for ChunkedReply {
        fn from(reply: PartialReadFile) -> Self {
            Self::PartialReadFile(reply)
        }
    }

    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct AppendFile {
        pub file_length: usize,
    }

    impl TryFrom<ChunkedReply> for AppendFile {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::AppendFile(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    impl From<AppendFile> for ChunkedReply {
        fn from(reply: AppendFile) -> Self {
            Self::AppendFile(reply)
        }
    }
}

pub type ChunkedResult<'a, R, C> = ExtensionResult<'a, ChunkedExtension, R, C>;

pub trait ChunkedClient: ExtensionClient<ChunkedExtension> + FilesystemClient {
    /// Begin writing a file that can be larger than 1KiB
    ///
    /// More chunks can be written with [`write_file_chunk`](ChunkedClient::write_file_chunk).
    /// The data is flushed and becomes readable when a chunk smaller than the maximum capacity of a `Message` is transfered.
    fn start_chunked_write(
        &mut self,
        location: Location,
        path: PathBuf,
        user_attribute: Option<UserAttribute>,
    ) -> ChunkedResult<'_, reply::StartChunkedWrite, Self> {
        self.extension(request::StartChunkedWrite {
            location,
            path,
            user_attribute,
        })
    }

    /// Begin writing an encrypted file that can be larger than 1KiB
    ///
    /// More chunks can be written with [`write_file_chunk`](ChunkedClient::write_file_chunk).
    /// The data is flushed and becomes readable when a chunk smaller than the maximum capacity of a [`Message`] is transfered.
    fn start_encrypted_chunked_write(
        &mut self,
        location: Location,
        path: PathBuf,
        key: KeyId,
        nonce: Option<ByteArray<CHACHA8_STREAM_NONCE_LEN>>,
        user_attribute: Option<UserAttribute>,
    ) -> ChunkedResult<'_, reply::StartEncryptedChunkedWrite, Self> {
        self.extension(request::StartEncryptedChunkedWrite {
            location,
            path,
            key,
            user_attribute,
            nonce,
        })
    }

    /// Begin reading a file that can be larger than 1KiB
    ///
    /// More chunks can be read with [`read_file_chunk`](ChunkedClient::read_file_chunk).
    /// The read is over once a chunk of size smaller than the maximum capacity of a [`Message`] is transfered.
    fn start_chunked_read(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ChunkedResult<'_, reply::StartChunkedRead, Self> {
        self.extension(request::StartChunkedRead { location, path })
    }

    /// Begin reading an encrypted file that can be larger than 1KiB
    ///
    /// More chunks can be read with [`read_file_chunk`](ChunkedClient::read_file_chunk).
    /// The read is over once a chunk of size smaller than the maximum capacity of a [`Message`] is transfered.
    /// Only once the entire file has been read does the data have been properly authenticated.
    fn start_encrypted_chunked_read(
        &mut self,
        location: Location,
        path: PathBuf,
        key: KeyId,
    ) -> ChunkedResult<'_, reply::StartEncryptedChunkedRead, Self> {
        self.extension(request::StartEncryptedChunkedRead {
            location,
            path,
            key,
        })
    }

    /// Write part of a file
    ///
    /// See [`start_chunked_write`](ChunkedClient::start_chunked_write).
    fn write_file_chunk(&mut self, data: Message) -> ChunkedResult<'_, reply::WriteChunk, Self> {
        self.extension(request::WriteChunk { data })
    }

    /// Abort writes to a file opened with [`start_chunked_write`](ChunkedClient::start_chunked_write).
    fn abort_chunked_write(&mut self) -> ChunkedResult<'_, reply::AbortChunkedWrite, Self> {
        self.extension(request::AbortChunkedWrite {})
    }

    // Read part of a file, up to 1KiB starting at `pos`
    fn read_file_chunk(&mut self) -> ChunkedResult<'_, reply::ReadChunk, Self> {
        self.extension(request::ReadChunk {})
    }

    /// Partially read a file from a given offset, returning a chunk of the given length and the
    /// total file size.
    ///
    /// If the length is greater than [`trussed::config::MAX_MESSAGE_LENGTH`][] or if the offset is
    /// greater than the file size, an error is returned.
    fn partial_read_file(
        &mut self,
        location: Location,
        path: PathBuf,
        offset: usize,
        length: usize,
    ) -> ChunkedResult<'_, reply::PartialReadFile, Self> {
        self.extension(request::PartialReadFile {
            location,
            path,
            offset,
            length,
        })
    }

    /// Append data to an existing file and return the size of the file after the write.
    fn append_file(
        &mut self,
        location: Location,
        path: PathBuf,
        data: Message,
    ) -> ChunkedResult<'_, reply::AppendFile, Self> {
        self.extension(request::AppendFile {
            location,
            path,
            data,
        })
    }
}

impl<C: ExtensionClient<ChunkedExtension> + FilesystemClient> ChunkedClient for C {}
