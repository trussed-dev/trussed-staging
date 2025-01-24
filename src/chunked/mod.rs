// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

mod store;
use store::OpenSeekFrom;

use chacha20poly1305::{
    aead::stream::{DecryptorLE31, EncryptorLE31, Nonce as StreamNonce, StreamLE31},
    ChaCha8Poly1305, KeyInit,
};
use rand_core::RngCore;
use trussed::{
    config::MAX_MESSAGE_LENGTH,
    key::{Kind, Secrecy},
    serde_extensions::ExtensionImpl,
    service::{Filestore, Keystore, ServiceResources},
    store::Store,
    types::{CoreContext, Location, Message, Path, PathBuf},
    Bytes, Error,
};
use trussed_chunked::{
    reply, ChunkedExtension, ChunkedReply, ChunkedRequest, CHACHA8_STREAM_NONCE_LEN,
};

use crate::StagingContext;

const POLY1305_TAG_LEN: usize = 16;
const CHACHA8_KEY_LEN: usize = 32;

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

pub struct EncryptedChunkedReadState {
    pub path: PathBuf,
    pub location: Location,
    pub offset: usize,
    pub decryptor: DecryptorLE31<ChaCha8Poly1305>,
}

pub struct EncryptedChunkedWriteState {
    pub path: PathBuf,
    pub location: Location,
    pub encryptor: EncryptorLE31<ChaCha8Poly1305>,
}

#[non_exhaustive]
pub enum ChunkedIoState {
    Read(ChunkedReadState),
    Write(ChunkedWriteState),
    EncryptedRead(EncryptedChunkedReadState),
    EncryptedWrite(EncryptedChunkedWriteState),
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
                    Some(ChunkedIoState::EncryptedRead(_)) => {
                        return read_encrypted_chunk(&store, client_id, backend_ctx)
                    }
                    _ => return Err(Error::MechanismNotAvailable),
                };
                let (data, len) = store::filestore_read_chunk(
                    &store,
                    client_id,
                    &read_state.path,
                    read_state.location,
                    OpenSeekFrom::Start(read_state.offset as u32),
                )?;

                read_state.offset += data.len();

                Ok(reply::ReadChunk { data, len }.into())
            }
            ChunkedRequest::StartChunkedRead(request) => {
                clear_chunked_state(&store, client_id, backend_ctx)?;
                let (data, len) = store::filestore_read_chunk(
                    &store,
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
                    write_last_chunk(&store, client_id, backend_ctx, &request.data)?;
                } else {
                    write_chunk(&store, client_id, backend_ctx, &request.data)?;
                }
                Ok(reply::WriteChunk {}.into())
            }
            ChunkedRequest::AbortChunkedWrite(_request) => {
                let Some(ChunkedIoState::Write(ref write_state)) = backend_ctx.chunked_io_state
                else {
                    return Ok(reply::AbortChunkedWrite { aborted: false }.into());
                };
                let aborted = store::abort_chunked_write(
                    &store,
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
                store::start_chunked_write(
                    &store,
                    client_id,
                    &request.path,
                    request.location,
                    &[],
                )?;
                Ok(reply::StartChunkedWrite {}.into())
            }
            ChunkedRequest::PartialReadFile(request) => {
                let (data, file_length) = store::partial_read_file(
                    &store,
                    client_id,
                    &request.path,
                    request.location,
                    request.offset,
                    request.length,
                )?;
                Ok(reply::PartialReadFile { data, file_length }.into())
            }
            ChunkedRequest::AppendFile(request) => {
                let file_length = store::append_file(
                    &store,
                    client_id,
                    &request.path,
                    request.location,
                    &request.data,
                )?;
                Ok(reply::AppendFile { file_length }.into())
            }
            ChunkedRequest::StartEncryptedChunkedWrite(request) => {
                clear_chunked_state(&store, client_id, backend_ctx)?;
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
                    &store,
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
            ChunkedRequest::StartEncryptedChunkedRead(request) => {
                clear_chunked_state(&store, client_id, backend_ctx)?;
                let key = keystore.load_key(
                    Secrecy::Secret,
                    Some(Kind::Symmetric(CHACHA8_KEY_LEN)),
                    &request.key,
                )?;
                let nonce: Bytes<CHACHA8_STREAM_NONCE_LEN> =
                    filestore.read(&request.path, request.location)?;
                let nonce: &StreamNonce<ChaCha8Poly1305, StreamLE31<ChaCha8Poly1305>> =
                    (&**nonce).into();
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
    store: &impl Store,
    client_id: &Path,
    ctx: &mut StagingContext,
) -> Result<(), Error> {
    match ctx.chunked_io_state.take() {
        Some(ChunkedIoState::Read(_)) | None => {}
        Some(ChunkedIoState::Write(write_state)) => {
            info!("Automatically cancelling write");
            store::abort_chunked_write(store, client_id, &write_state.path, write_state.location);
        }
        Some(ChunkedIoState::EncryptedRead(_)) => {}
        Some(ChunkedIoState::EncryptedWrite(write_state)) => {
            info!("Automatically cancelling encrypted write");
            store::abort_chunked_write(store, client_id, &write_state.path, write_state.location);
        }
    }
    Ok(())
}

fn write_chunk(
    store: &impl Store,
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
    store: &impl Store,
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

fn read_encrypted_chunk(
    store: &impl Store,
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
