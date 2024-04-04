// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use serde_byte_array::ByteArray;
use trussed::{
    error::Error,
    syscall, try_syscall,
    types::{KeyId, Location, Message, PathBuf, UserAttribute},
};

use crate::{ChunkedClient, CHACHA8_STREAM_NONCE_LEN};

#[derive(Clone, Copy)]
pub struct EncryptionData {
    pub key: KeyId,
    pub nonce: Option<ByteArray<CHACHA8_STREAM_NONCE_LEN>>,
}

/// Write a large file (can be larger than 1KiB)
///
/// This is a wrapper around the [chunked writes api](ChunkedClient)
pub fn write_all(
    client: &mut impl ChunkedClient,
    location: Location,
    path: PathBuf,
    data: &[u8],
    user_attribute: Option<UserAttribute>,
    encryption: Option<EncryptionData>,
) -> Result<(), Error> {
    if let (Ok(msg), None) = (Message::from_slice(data), encryption) {
        // Fast path for small files
        try_syscall!(client.write_file(location, path, msg, user_attribute))?;
        Ok(())
    } else {
        write_chunked(client, location, path, data, user_attribute, encryption)
    }
}

fn write_chunked(
    client: &mut impl ChunkedClient,
    location: Location,
    path: PathBuf,
    data: &[u8],
    user_attribute: Option<UserAttribute>,
    encryption: Option<EncryptionData>,
) -> Result<(), Error> {
    let res = write_chunked_inner(client, location, path, data, user_attribute, encryption);
    if res.is_err() {
        syscall!(client.abort_chunked_write());
        return res;
    }
    Ok(())
}

fn write_chunked_inner(
    client: &mut impl ChunkedClient,
    location: Location,
    path: PathBuf,
    data: &[u8],
    user_attribute: Option<UserAttribute>,
    encryption: Option<EncryptionData>,
) -> Result<(), Error> {
    let msg = Message::new();
    let chunk_size = msg.capacity();
    let chunks = data.chunks(chunk_size).map(|chunk| {
        Message::from_slice(chunk).expect("Iteration over chunks yields maximum of chunk_size")
    });
    if let Some(encryption_data) = encryption {
        try_syscall!(client.start_encrypted_chunked_write(
            location,
            path,
            encryption_data.key,
            encryption_data.nonce,
            user_attribute,
        ))?;
    } else {
        try_syscall!(client.start_chunked_write(location, path, user_attribute))?;
    }
    let mut written = 0;
    for chunk in chunks {
        written += chunk.len();
        try_syscall!(client.write_file_chunk(chunk))?;
    }

    if { written % chunk_size } == 0 {
        try_syscall!(client.write_file_chunk(Message::new()))?;
    }
    Ok(())
}
