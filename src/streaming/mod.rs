// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

mod store;
use store::OpenSeekFrom;

#[cfg(feature = "encrypted-chunked")]
pub mod utils;

#[cfg(feature = "encrypted-chunked")]
use chacha20poly1305::{
    aead::stream::{DecryptorLE31, EncryptorLE31, Nonce as StreamNonce, StreamLE31},
    ChaCha8Poly1305, KeyInit,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use trussed::{
    client::FilesystemClient,
    config::MAX_MESSAGE_LENGTH,
    key::{Kind, Secrecy},
    serde_extensions::{Extension, ExtensionClient, ExtensionImpl, ExtensionResult},
    service::{Filestore, Keystore, ServiceResources},
    store::Store,
    types::{CoreContext, KeyId, Location, Message, Path, PathBuf, UserAttribute},
    Bytes, Error,
};

use crate::StagingContext;

#[derive(Debug)]
pub struct ChunkedReadState {
    pub path: PathBuf,
    pub location: Location,
    pub offset: usize,
}

#[derive(Debug)]
pub struct ChunkedWriteState {
    pub path: PathBuf,
    pub location: Location,
}

#[cfg(feature = "encrypted-chunked")]
pub struct EncryptedChunkedReadState {
    pub path: PathBuf,
    pub location: Location,
    pub offset: usize,
    pub decryptor: DecryptorLE31<ChaCha8Poly1305>,
}

#[cfg(feature = "encrypted-chunked")]
pub struct EncryptedChunkedWriteState {
    pub path: PathBuf,
    pub location: Location,
    pub encryptor: EncryptorLE31<ChaCha8Poly1305>,
}

#[non_exhaustive]
pub enum ChunkedIoState {
    Read(ChunkedReadState),
    Write(ChunkedWriteState),
    #[cfg(feature = "encrypted-chunked")]
    EncryptedRead(EncryptedChunkedReadState),
    #[cfg(feature = "encrypted-chunked")]
    EncryptedWrite(EncryptedChunkedWriteState),
}

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
    #[cfg(feature = "encrypted-chunked")]
    StartEncryptedChunkedWrite(request::StartEncryptedChunkedWrite),
    StartChunkedRead(request::StartChunkedRead),
    #[cfg(feature = "encrypted-chunked")]
    StartEncryptedChunkedRead(request::StartEncryptedChunkedRead),
    ReadChunk(request::ReadChunk),
    WriteChunk(request::WriteChunk),
    AbortChunkedWrite(request::AbortChunkedWrite),
    PartialReadFile(request::PartialReadFile),
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum ChunkedReply {
    ReadChunk(reply::ReadChunk),
    StartChunkedWrite(reply::StartChunkedWrite),
    #[cfg(feature = "encrypted-chunked")]
    StartEncryptedChunkedWrite(reply::StartEncryptedChunkedWrite),
    StartChunkedRead(reply::StartChunkedRead),
    #[cfg(feature = "encrypted-chunked")]
    StartEncryptedChunkedRead(reply::StartEncryptedChunkedRead),
    WriteChunk(reply::WriteChunk),
    AbortChunkedWrite(reply::AbortChunkedWrite),
    PartialReadFile(reply::PartialReadFile),
}

mod request {
    use super::*;
    use serde::{Deserialize, Serialize};
    use serde_byte_array::ByteArray;
    use trussed::types::{KeyId, Location, Message, PathBuf, UserAttribute};
    use trussed::Error;

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

    #[cfg(feature = "encrypted-chunked")]
    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartEncryptedChunkedWrite {
        pub location: Location,
        pub path: PathBuf,
        pub user_attribute: Option<UserAttribute>,
        pub key: KeyId,
        pub nonce: Option<ByteArray<CHACHA8_STREAM_NONCE_LEN>>,
    }

    #[cfg(feature = "encrypted-chunked")]
    impl TryFrom<ChunkedRequest> for StartEncryptedChunkedWrite {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::StartEncryptedChunkedWrite(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    #[cfg(feature = "encrypted-chunked")]
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

    #[cfg(feature = "encrypted-chunked")]
    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartEncryptedChunkedRead {
        pub location: Location,
        pub path: PathBuf,
        pub key: KeyId,
    }

    #[cfg(feature = "encrypted-chunked")]
    impl TryFrom<ChunkedRequest> for StartEncryptedChunkedRead {
        type Error = Error;
        fn try_from(request: ChunkedRequest) -> Result<Self, Self::Error> {
            match request {
                ChunkedRequest::StartEncryptedChunkedRead(request) => Ok(request),
                _ => Err(Error::InternalError),
            }
        }
    }

    #[cfg(feature = "encrypted-chunked")]
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
}

mod reply {
    use super::*;
    use serde::{Deserialize, Serialize};
    use trussed::types::Message;
    use trussed::Error;

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

    #[cfg(feature = "encrypted-chunked")]
    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartEncryptedChunkedWrite {}

    #[cfg(feature = "encrypted-chunked")]
    impl TryFrom<ChunkedReply> for StartEncryptedChunkedWrite {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::StartEncryptedChunkedWrite(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    #[cfg(feature = "encrypted-chunked")]
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

    #[cfg(feature = "encrypted-chunked")]
    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct StartEncryptedChunkedRead {}

    #[cfg(feature = "encrypted-chunked")]
    impl TryFrom<ChunkedReply> for StartEncryptedChunkedRead {
        type Error = Error;
        fn try_from(reply: ChunkedReply) -> Result<Self, Self::Error> {
            match reply {
                ChunkedReply::StartEncryptedChunkedRead(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    #[cfg(feature = "encrypted-chunked")]
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
}

impl ExtensionImpl<ChunkedExtension> for super::StagingBackend {
    fn extension_request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &ChunkedRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<ChunkedReply, Error> {
        let rng = &mut resources.rng()?;
        let keystore = &mut resources.keystore(core_ctx.path.clone())?;
        let filestore = &mut resources.filestore(core_ctx.path.clone());
        let client_id = &core_ctx.path;
        let store = resources.platform_mut().store();
        match request {
            ChunkedRequest::ReadChunk(_) => {
                let read_state = match &mut backend_ctx.chunked_io_state {
                    Some(ChunkedIoState::Read(read_state)) => read_state,
                    #[cfg(feature = "encrypted-chunked")]
                    Some(ChunkedIoState::EncryptedRead(_)) => {
                        return read_encrypted_chunk(store, client_id, backend_ctx)
                    }
                    _ => return Err(Error::MechanismNotAvailable),
                };
                let (data, len) = store::filestore_read_chunk(
                    store,
                    client_id,
                    &read_state.path,
                    read_state.location,
                    OpenSeekFrom::Start(read_state.offset as u32),
                )?;

                read_state.offset += data.len();

                Ok(reply::ReadChunk { data, len }.into())
            }
            ChunkedRequest::StartChunkedRead(request) => {
                clear_chunked_state(store, client_id, backend_ctx)?;
                let (data, len) = store::filestore_read_chunk(
                    store,
                    client_id,
                    &request.path,
                    request.location,
                    OpenSeekFrom::Start(0),
                )?;
                backend_ctx.chunked_io_state = Some(ChunkedIoState::Read(ChunkedReadState {
                    path: request.path.clone(),
                    location: request.location,
                    offset: data.len(),
                }));
                Ok(reply::StartChunkedRead { data, len }.into())
            }
            ChunkedRequest::WriteChunk(request) => {
                let is_last = !request.data.is_full();
                if is_last {
                    write_last_chunk(store, client_id, backend_ctx, &request.data)?;
                } else {
                    write_chunk(store, client_id, backend_ctx, &request.data)?;
                }
                Ok(reply::WriteChunk {}.into())
            }
            ChunkedRequest::AbortChunkedWrite(_request) => {
                let Some(ChunkedIoState::Write(ref write_state)) = backend_ctx.chunked_io_state
                else {
                    return Ok(reply::AbortChunkedWrite { aborted: false }.into());
                };
                let aborted = store::abort_chunked_write(
                    store,
                    client_id,
                    &write_state.path,
                    write_state.location,
                );
                Ok(reply::AbortChunkedWrite { aborted }.into())
            }
            ChunkedRequest::StartChunkedWrite(request) => {
                backend_ctx.chunked_io_state = Some(ChunkedIoState::Write(ChunkedWriteState {
                    path: request.path.clone(),
                    location: request.location,
                }));
                store::start_chunked_write(store, client_id, &request.path, request.location, &[])?;
                Ok(reply::StartChunkedWrite {}.into())
            }
            ChunkedRequest::PartialReadFile(request) => {
                let (data, file_length) = store::partial_read_file(
                    store,
                    client_id,
                    &request.path,
                    request.location,
                    request.offset,
                    request.length,
                )?;
                Ok(reply::PartialReadFile { data, file_length }.into())
            }
            #[cfg(feature = "encrypted-chunked")]
            ChunkedRequest::StartEncryptedChunkedWrite(request) => {
                clear_chunked_state(store, client_id, backend_ctx)?;
                let key = keystore.load_key(
                    Secrecy::Secret,
                    Some(Kind::Symmetric(CHACHA8_KEY_LEN)),
                    &request.key,
                )?;
                let nonce = request.nonce.map(|n| *n).unwrap_or_else(|| {
                    let mut nonce = [0; CHACHA8_STREAM_NONCE_LEN];
                    rng.fill_bytes(&mut nonce);
                    nonce
                });
                let nonce: &StreamNonce<ChaCha8Poly1305, StreamLE31<ChaCha8Poly1305>> =
                    (&nonce).into();
                let aead = ChaCha8Poly1305::new((&*key.material).into());
                let encryptor = EncryptorLE31::<ChaCha8Poly1305>::from_aead(aead, nonce);
                store::start_chunked_write(
                    store,
                    client_id,
                    &request.path,
                    request.location,
                    nonce,
                )?;
                backend_ctx.chunked_io_state =
                    Some(ChunkedIoState::EncryptedWrite(EncryptedChunkedWriteState {
                        path: request.path.clone(),
                        location: request.location,
                        encryptor,
                    }));
                Ok(reply::StartEncryptedChunkedWrite {}.into())
            }
            #[cfg(feature = "encrypted-chunked")]
            ChunkedRequest::StartEncryptedChunkedRead(request) => {
                clear_chunked_state(store, client_id, backend_ctx)?;
                let key = keystore.load_key(
                    Secrecy::Secret,
                    Some(Kind::Symmetric(CHACHA8_KEY_LEN)),
                    &request.key,
                )?;
                let nonce: Bytes<CHACHA8_STREAM_NONCE_LEN> =
                    filestore.read(&request.path, request.location)?;
                let nonce: &StreamNonce<ChaCha8Poly1305, StreamLE31<ChaCha8Poly1305>> = (&**nonce)
                    .try_into()
                    .map_err(|_| Error::WrongMessageLength)?;
                let aead = ChaCha8Poly1305::new((&*key.material).into());
                let decryptor = DecryptorLE31::<ChaCha8Poly1305>::from_aead(aead, nonce);
                backend_ctx.chunked_io_state =
                    Some(ChunkedIoState::EncryptedRead(EncryptedChunkedReadState {
                        path: request.path.clone(),
                        location: request.location,
                        decryptor,
                        offset: CHACHA8_STREAM_NONCE_LEN,
                    }));
                Ok(reply::StartEncryptedChunkedRead {}.into())
            }
        }
    }
}

fn clear_chunked_state(
    store: impl Store,
    client_id: &Path,
    ctx: &mut StagingContext,
) -> Result<(), Error> {
    match ctx.chunked_io_state.take() {
        Some(ChunkedIoState::Read(_)) | None => {}
        Some(ChunkedIoState::Write(write_state)) => {
            info!("Automatically cancelling write");
            store::abort_chunked_write(store, client_id, &write_state.path, write_state.location);
        }
        #[cfg(feature = "encrypted-chunked")]
        Some(ChunkedIoState::EncryptedRead(_)) => {}
        #[cfg(feature = "encrypted-chunked")]
        Some(ChunkedIoState::EncryptedWrite(write_state)) => {
            info!("Automatically cancelling encrypted write");
            store::abort_chunked_write(store, client_id, &write_state.path, write_state.location);
        }
    }
    Ok(())
}

fn write_chunk(
    store: impl Store,
    client_id: &Path,
    ctx: &mut StagingContext,
    data: &Message,
) -> Result<(), Error> {
    match ctx.chunked_io_state {
        Some(ChunkedIoState::Write(ref write_state)) => {
            store::filestore_write_chunk(
                store,
                client_id,
                &write_state.path,
                write_state.location,
                data,
            )?;
        }
        #[cfg(feature = "encrypted-chunked")]
        Some(ChunkedIoState::EncryptedWrite(ref mut write_state)) => {
            let mut data =
                Bytes::<{ MAX_MESSAGE_LENGTH + POLY1305_TAG_LEN }>::from_slice(data).unwrap();
            write_state
                .encryptor
                .encrypt_next_in_place(write_state.path.as_ref().as_bytes(), &mut *data)
                .map_err(|_err| {
                    error!("Failed to encrypt {:?}", _err);
                    Error::AeadError
                })?;
            store::filestore_write_chunk(
                store,
                client_id,
                &write_state.path,
                write_state.location,
                &data,
            )?;
        }
        _ => return Err(Error::MechanismNotAvailable),
    }
    Ok(())
}

fn write_last_chunk(
    store: impl Store,
    client_id: &Path,
    ctx: &mut StagingContext,
    data: &Message,
) -> Result<(), Error> {
    match ctx.chunked_io_state.take() {
        Some(ChunkedIoState::Write(write_state)) => {
            store::filestore_write_chunk(
                store,
                client_id,
                &write_state.path,
                write_state.location,
                data,
            )?;
            store::flush_chunks(store, client_id, &write_state.path, write_state.location)?;
        }
        #[cfg(feature = "encrypted-chunked")]
        Some(ChunkedIoState::EncryptedWrite(write_state)) => {
            let mut data =
                Bytes::<{ MAX_MESSAGE_LENGTH + POLY1305_TAG_LEN }>::from_slice(data).unwrap();
            write_state
                .encryptor
                .encrypt_last_in_place(&[write_state.location as u8], &mut *data)
                .map_err(|_err| {
                    error!("Failed to encrypt {:?}", _err);
                    Error::AeadError
                })?;
            store::filestore_write_chunk(
                store,
                client_id,
                &write_state.path,
                write_state.location,
                &data,
            )?;
            store::flush_chunks(store, client_id, &write_state.path, write_state.location)?;
        }
        _ => return Err(Error::MechanismNotAvailable),
    }

    Ok(())
}

#[cfg(feature = "encrypted-chunked")]
fn read_encrypted_chunk(
    store: impl Store,
    client_id: &Path,
    ctx: &mut StagingContext,
) -> Result<ChunkedReply, Error> {
    let Some(ChunkedIoState::EncryptedRead(ref mut read_state)) = ctx.chunked_io_state else {
        unreachable!(
            "Read encrypted chunk can only be called in the context encrypted chunk reads"
        );
    };
    let (mut data, len): (Bytes<{ MAX_MESSAGE_LENGTH + POLY1305_TAG_LEN }>, usize) =
        store::filestore_read_chunk(
            store,
            client_id,
            &read_state.path,
            read_state.location,
            OpenSeekFrom::Start(read_state.offset as _),
        )?;
    read_state.offset += data.len();

    let is_last = !data.is_full();
    if is_last {
        let Some(ChunkedIoState::EncryptedRead(read_state)) = ctx.chunked_io_state.take() else {
            unreachable!();
        };

        read_state
            .decryptor
            .decrypt_last_in_place(&[read_state.location as u8], &mut *data)
            .map_err(|_err| {
                error!("Failed to decrypt {:?}", _err);
                Error::AeadError
            })?;
        let data = Bytes::from_slice(&data).expect("decryptor removes the tag");
        Ok(reply::ReadChunk {
            data,
            len: chunked_decrypted_len(len)?,
        }
        .into())
    } else {
        read_state
            .decryptor
            .decrypt_next_in_place(read_state.path.as_ref().as_bytes(), &mut *data)
            .map_err(|_err| {
                error!("Failed to decrypt {:?}", _err);
                Error::AeadError
            })?;
        let data = Bytes::from_slice(&data).expect("decryptor removes the tag");
        Ok(reply::ReadChunk {
            data,
            len: chunked_decrypted_len(len)?,
        }
        .into())
    }
}

pub const POLY1305_TAG_LEN: usize = 16;
pub const CHACHA8_KEY_LEN: usize = 32;
pub const CHACHA8_STREAM_NONCE_LEN: usize = 8;
/// Calculate the decrypted length of a chunked encrypted file
fn chunked_decrypted_len(len: usize) -> Result<usize, Error> {
    let len = len.checked_sub(CHACHA8_STREAM_NONCE_LEN).ok_or_else(|| {
        error!("File too small");
        Error::FilesystemReadFailure
    })?;
    const CHUNK_LEN: usize = POLY1305_TAG_LEN + MAX_MESSAGE_LENGTH;
    let chunk_count = len / CHUNK_LEN;
    let last_chunk_len = (len % CHUNK_LEN)
        .checked_sub(POLY1305_TAG_LEN)
        .ok_or_else(|| {
            error!("Incorrect last chunk length");
            Error::FilesystemReadFailure
        })?;

    Ok(chunk_count * MAX_MESSAGE_LENGTH + last_chunk_len)
}

type ChunkedResult<'a, R, C> = ExtensionResult<'a, ChunkedExtension, R, C>;

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
    #[cfg(feature = "encrypted-chunked")]
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
    #[cfg(feature = "encrypted-chunked")]
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
}

impl<C: ExtensionClient<ChunkedExtension> + FilesystemClient> ChunkedClient for C {}
