// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use littlefs2::fs::OpenOptions;
use littlefs2::io::SeekFrom;
use littlefs2::object_safe::{DynFile, DynFilesystem};

use trussed::error::Error;
use trussed::store::{create_directories, Store};
use trussed::types::{Bytes, Location, Message, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Enumeration of possible methods to seek within an file that was just opened
/// Used in the [`read_chunk`](crate::store::read_chunk) and [`write_chunk`](crate::store::write_chunk) calls,
/// Where [`SeekFrom::Current`](littlefs2::io::SeekFrom::Current) would not make sense.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OpenSeekFrom {
    Start(u32),
    End(i32),
}

impl From<OpenSeekFrom> for SeekFrom {
    fn from(value: OpenSeekFrom) -> Self {
        match value {
            OpenSeekFrom::Start(o) => Self::Start(o),
            OpenSeekFrom::End(o) => Self::End(o),
        }
    }
}

pub fn fs_read_chunk<const N: usize>(
    fs: &dyn DynFilesystem,
    path: &Path,
    pos: OpenSeekFrom,
    length: usize,
) -> Result<(Bytes<N>, usize), Error> {
    let mut contents = Bytes::default();
    if length > contents.capacity() {
        return Err(Error::FilesystemReadFailure);
    }
    contents.resize_default(length).unwrap();
    let file_len = fs
        .open_file_and_then(path, &mut |file| {
            file.seek(pos.into())?;
            let read_n = file.read(&mut contents)?;
            contents.truncate(read_n);
            file.len()
        })
        .map_err(|_| Error::FilesystemReadFailure)?;
    Ok((contents, file_len))
}

/// Reads contents from path in location of store.
#[inline(never)]
pub fn read_chunk<const N: usize>(
    store: impl Store,
    location: Location,
    path: &Path,
    pos: OpenSeekFrom,
) -> Result<(Bytes<N>, usize), Error> {
    debug_now!("reading chunk {},{:?}", &path, pos);
    fs_read_chunk(store.fs(location), path, pos, N)
}

pub fn fs_write_chunk(
    fs: &dyn DynFilesystem,
    path: &Path,
    contents: &[u8],
    pos: OpenSeekFrom,
) -> Result<(), Error> {
    fs.open_file_with_options_and_then(
        &|options| options.read(true).write(true),
        path,
        &mut |file| {
            file.seek(pos.into())?;
            file.write_all(contents)
        },
    )
    .map_err(|_| Error::FilesystemReadFailure)
}

/// Writes contents to path in location of store.
#[inline(never)]
pub fn write_chunk(
    store: impl Store,
    location: Location,
    path: &Path,
    contents: &[u8],
    pos: OpenSeekFrom,
) -> Result<(), Error> {
    debug_now!("writing {}", &path);
    fs_write_chunk(store.fs(location), path, contents, pos)
        .map_err(|_| Error::FilesystemWriteFailure)
}

pub fn move_file(
    store: impl Store,
    from_location: Location,
    from_path: &Path,
    to_location: Location,
    to_path: &Path,
) -> Result<(), Error> {
    debug_now!(
        "Moving {:?}({}) to {:?}({})",
        from_location,
        from_path,
        to_location,
        to_path
    );

    create_directories(store.fs(to_location), to_path).map_err(|_err| {
        error!("Failed to create directories chunks: {:?}", _err);
        Error::FilesystemWriteFailure
    })?;

    let on_fail = |_err| {
        error!("Failed to rename file: {:?}", _err);
        Error::FilesystemWriteFailure
    };
    // Fast path for same-filesystem
    if from_location == to_location {
        return store
            .fs(from_location)
            .rename(from_path, to_path)
            .map_err(on_fail);
    }

    store
        .fs(from_location)
        .open_file_and_then(from_path, &mut |from_file| {
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);
            store
                .fs(to_location)
                .create_file_and_then(to_path, &mut |to_file| copy_file_data(from_file, to_file))
        })
        .map_err(|_err| {
            error!("Failed to flush chunks: {:?}", _err);
            Error::FilesystemWriteFailure
        })
}

fn copy_file_data(from: &dyn DynFile, to: &dyn DynFile) -> Result<(), littlefs2::io::Error> {
    let mut buf = [0; 1024];
    loop {
        let read = from.read(&mut buf)?;
        if read == 0 {
            return Ok(());
        }

        to.write_all(&buf[..read])?;
    }
}

fn chunks_path(client_id: &Path, client_path: &Path, location: Location) -> Result<PathBuf, Error> {
    // Clients must not escape their namespace
    if client_path.as_ref().contains("..") {
        return Err(Error::InvalidPath);
    }

    let mut path = PathBuf::new();
    path.push(client_id);
    match location {
        Location::Volatile => path.push(&PathBuf::from("vfs-part")),
        Location::External => path.push(&PathBuf::from("efs-part")),
        Location::Internal => path.push(&PathBuf::from("ifs-part")),
    }
    path.push(client_path);
    Ok(path)
}

fn actual_path(client_id: &Path, client_path: &Path) -> Result<PathBuf, Error> {
    // Clients must not escape their namespace
    if client_path.as_ref().contains("..") {
        return Err(Error::InvalidPath);
    }

    let mut path = PathBuf::new();
    path.push(client_id);
    path.push(&PathBuf::from("dat"));
    path.push(client_path);
    Ok(path)
}

pub fn start_chunked_write(
    store: impl Store,
    client_id: &Path,
    path: &PathBuf,
    location: Location,
    data: &[u8],
) -> Result<(), Error> {
    let path = chunks_path(client_id, path, location)?;
    trussed::store::store(store, Location::Volatile, &path, data)
}

pub fn filestore_write_chunk(
    store: impl Store,
    client_id: &Path,
    path: &Path,
    location: Location,
    data: &[u8],
) -> Result<(), Error> {
    let path = chunks_path(client_id, path, location)?;
    write_chunk(store, Location::Volatile, &path, data, OpenSeekFrom::End(0))
}

pub fn filestore_read_chunk<const N: usize>(
    store: impl Store,
    client_id: &Path,
    path: &PathBuf,
    location: Location,
    pos: OpenSeekFrom,
) -> Result<(Bytes<N>, usize), Error> {
    let path = actual_path(client_id, path)?;

    read_chunk(store, location, &path, pos)
}

pub fn abort_chunked_write(
    store: impl Store,
    client_id: &Path,
    path: &PathBuf,
    location: Location,
) -> bool {
    let Ok(path) = chunks_path(client_id, path, location) else {
        return false;
    };
    trussed::store::delete(store, Location::Volatile, &path)
}

pub fn flush_chunks(
    store: impl Store,
    client_id: &Path,
    path: &PathBuf,
    location: Location,
) -> Result<(), Error> {
    let chunk_path = chunks_path(client_id, path, location)?;
    let client_path = actual_path(client_id, path)?;
    move_file(
        store,
        Location::Volatile,
        &chunk_path,
        location,
        &client_path,
    )
}

pub fn partial_read_file(
    store: impl Store,
    client_id: &Path,
    path: &PathBuf,
    location: Location,
    offset: usize,
    length: usize,
) -> Result<(Message, usize), Error> {
    let path = actual_path(client_id, path)?;
    let offset = u32::try_from(offset).map_err(|_| Error::FilesystemReadFailure)?;
    let pos = OpenSeekFrom::Start(offset);
    fs_read_chunk(store.fs(location), &path, pos, length)
}

pub fn append_file(
    store: impl Store,
    client_id: &Path,
    path: &PathBuf,
    location: Location,
    data: &[u8],
) -> Result<usize, Error> {
    let path = actual_path(client_id, path)?;
    store
        .fs(location)
        .open_file_with_options_and_then(
            &|options| options.write(true).append(true),
            &path,
            &mut |file| {
                file.write_all(data)?;
                file.len()
            },
        )
        .map_err(|_| Error::FilesystemWriteFailure)
}
