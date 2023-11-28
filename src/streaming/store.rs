// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use littlefs2::driver::Storage as LfsStorage;
use littlefs2::fs::{File, Filesystem, OpenOptions};
use littlefs2::io::{SeekFrom, Write};

use trussed::store::{create_directories, Store};
use trussed::types::{Bytes, Location, Message, Path, PathBuf};
use trussed::Error;

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

pub fn fs_read_chunk<Storage: LfsStorage, const N: usize>(
    fs: &Filesystem<Storage>,
    path: &Path,
    pos: OpenSeekFrom,
    length: usize,
) -> Result<(Bytes<N>, usize), Error> {
    let mut contents = Bytes::default();
    if length > contents.capacity() {
        return Err(Error::FilesystemReadFailure);
    }
    contents.resize_default(length).unwrap();
    let file_len = File::open_and_then(fs, path, |file| {
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
    match location {
        Location::Internal => fs_read_chunk(store.ifs(), path, pos, N),
        Location::External => fs_read_chunk(store.efs(), path, pos, N),
        Location::Volatile => fs_read_chunk(store.vfs(), path, pos, N),
    }
}

pub fn fs_write_chunk<Storage: LfsStorage>(
    fs: &Filesystem<Storage>,
    path: &Path,
    contents: &[u8],
    pos: OpenSeekFrom,
) -> Result<(), Error> {
    File::<Storage>::with_options()
        .read(true)
        .write(true)
        .open_and_then(fs, path, |file| {
            file.seek(pos.into())?;
            file.write_all(contents)
        })
        .map_err(|_| Error::FilesystemReadFailure)?;
    Ok(())
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
    match location {
        Location::Internal => fs_write_chunk(store.ifs(), path, contents, pos),
        Location::External => fs_write_chunk(store.efs(), path, contents, pos),
        Location::Volatile => fs_write_chunk(store.vfs(), path, contents, pos),
    }
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

    match to_location {
        Location::Internal => create_directories(store.ifs(), to_path),
        Location::External => create_directories(store.efs(), to_path),
        Location::Volatile => create_directories(store.vfs(), to_path),
    }
    .map_err(|_err| {
        error!("Failed to create directories chunks: {:?}", _err);
        Error::FilesystemWriteFailure
    })?;

    let on_fail = |_err| {
        error!("Failed to rename file: {:?}", _err);
        Error::FilesystemWriteFailure
    };
    // Fast path for same-filesystem
    match (from_location, to_location) {
        (Location::Internal, Location::Internal) => {
            return store.ifs().rename(from_path, to_path).map_err(on_fail)
        }
        (Location::External, Location::External) => {
            return store.efs().rename(from_path, to_path).map_err(on_fail)
        }
        (Location::Volatile, Location::Volatile) => {
            return store.vfs().rename(from_path, to_path).map_err(on_fail)
        }
        _ => {}
    }

    match from_location {
        Location::Internal => {
            move_file_step1(store, &**store.ifs(), from_path, to_location, to_path)
        }
        Location::External => {
            move_file_step1(store, &**store.efs(), from_path, to_location, to_path)
        }
        Location::Volatile => {
            move_file_step1(store, &**store.vfs(), from_path, to_location, to_path)
        }
    }
}

// Separate generic function to avoid having 9 times the same code because the filesystem types are not the same.
fn move_file_step1<S: LfsStorage>(
    store: impl Store,
    from_fs: &Filesystem<S>,
    from_path: &Path,
    to_location: Location,
    to_path: &Path,
) -> Result<(), Error> {
    match to_location {
        Location::Internal => move_file_step2(from_fs, from_path, &**store.ifs(), to_path),
        Location::External => move_file_step2(from_fs, from_path, &**store.efs(), to_path),
        Location::Volatile => move_file_step2(from_fs, from_path, &**store.vfs(), to_path),
    }
}

// Separate generic function to avoid having 9 times the same code because the filesystem types are not the same.
fn move_file_step2<S1: LfsStorage, S2: LfsStorage>(
    from_fs: &Filesystem<S1>,
    from_path: &Path,
    to_fs: &Filesystem<S2>,
    to_path: &Path,
) -> Result<(), Error> {
    File::open_and_then(from_fs, from_path, |from_file| {
        File::create_and_then(to_fs, to_path, |to_file| copy_file_data(from_file, to_file))
    })
    .map_err(|_err| {
        error!("Failed to flush chunks: {:?}", _err);
        Error::FilesystemWriteFailure
    })
}

fn copy_file_data<S1: LfsStorage, S2: LfsStorage>(
    from: &File<S1>,
    to: &File<S2>,
) -> Result<(), littlefs2::io::Error> {
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
    match location {
        Location::Internal => fs_read_chunk(store.ifs(), &path, pos, length),
        Location::External => fs_read_chunk(store.efs(), &path, pos, length),
        Location::Volatile => fs_read_chunk(store.vfs(), &path, pos, length),
    }
}

fn fs_append_file<Storage: LfsStorage>(
    fs: &Filesystem<Storage>,
    path: &Path,
    data: &[u8],
) -> Result<usize, Error> {
    OpenOptions::new()
        .write(true)
        .append(true)
        .open_and_then(fs, path, |file| {
            file.write_all(data)?;
            file.len()
        })
        .map_err(|_| Error::FilesystemWriteFailure)
}

pub fn append_file(
    store: impl Store,
    client_id: &Path,
    path: &PathBuf,
    location: Location,
    data: &[u8],
) -> Result<usize, Error> {
    let path = actual_path(client_id, path)?;
    match location {
        Location::Internal => fs_append_file(store.ifs(), &path, data),
        Location::External => fs_append_file(store.efs(), &path, data),
        Location::Volatile => fs_append_file(store.vfs(), &path, data),
    }
}
