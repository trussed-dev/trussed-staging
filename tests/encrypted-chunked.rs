// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(all(feature = "virt", feature = "encrypted-chunked"))]

use littlefs2::path::PathBuf;
use serde_byte_array::ByteArray;
use trussed::{
    client::CryptoClient, client::FilesystemClient, syscall, try_syscall, types::Location, Bytes,
    Error,
};
use trussed_staging::{
    streaming::{
        utils::{self, EncryptionData},
        ChunkedClient,
    },
    virt::with_ram_client,
};

fn test_write_all(location: Location) {
    with_ram_client("test chunked", |mut client| {
        let key = syscall!(client.generate_secret_key(32, Location::Volatile)).key;
        let path = PathBuf::from("foo");
        utils::write_all(
            &mut client,
            location,
            path.clone(),
            &[48; 1234],
            None,
            Some(EncryptionData { key, nonce: None }),
        )
        .unwrap();

        syscall!(client.start_encrypted_chunked_read(location, path, key));
        let data = syscall!(client.read_file_chunk()).data;
        assert_eq!(&data, &[48; 1024]);
        let data = syscall!(client.read_file_chunk()).data;
        assert_eq!(&data, &[48; 1234 - 1024]);
    });
}

fn test_write_all_small(location: Location) {
    with_ram_client("test chunked", |mut client| {
        let key = syscall!(client.generate_secret_key(32, Location::Volatile)).key;
        let path = PathBuf::from("foo2");
        utils::write_all(
            &mut client,
            location,
            path.clone(),
            &[48; 1023],
            None,
            Some(EncryptionData { key, nonce: None }),
        )
        .unwrap();

        syscall!(client.start_encrypted_chunked_read(location, path, key));
        let data = syscall!(client.read_file_chunk()).data;
        assert_eq!(&data, &[48; 1023]);
    });
}

#[test]
fn write_all_volatile() {
    test_write_all(Location::Volatile);
    test_write_all_small(Location::Volatile);
}

#[test]
fn write_all_external() {
    test_write_all(Location::External);
    test_write_all_small(Location::External);
}

#[test]
fn write_all_internal() {
    test_write_all(Location::Internal);
    test_write_all_small(Location::Internal);
}

#[test]
fn encrypted_filesystem() {
    with_ram_client("chunked-tests", |mut client| {
        let key = syscall!(client.generate_secret_key(32, Location::Volatile)).key;

        assert!(
            syscall!(client.entry_metadata(Location::Internal, PathBuf::from("test_file")))
                .metadata
                .is_none(),
        );

        let large_data = Bytes::from_slice(&[0; 1024]).unwrap();
        let large_data2 = Bytes::from_slice(&[1; 1024]).unwrap();
        let more_data = Bytes::from_slice(&[2; 42]).unwrap();
        // ======== CHUNKED WRITES ========
        syscall!(client.start_encrypted_chunked_write(
            Location::Internal,
            PathBuf::from("test_file"),
            key,
            Some(ByteArray::from([0; 8])),
            None
        ));

        syscall!(client.write_file_chunk(large_data.clone()));
        syscall!(client.write_file_chunk(large_data2.clone()));
        syscall!(client.write_file_chunk(more_data.clone()));

        // ======== CHUNKED READS ========
        let full_len = large_data.len() + large_data2.len() + more_data.len();
        syscall!(client.start_encrypted_chunked_read(
            Location::Internal,
            PathBuf::from("test_file"),
            key
        ));
        let first_data = syscall!(client.read_file_chunk());
        assert_eq!(&first_data.data, &large_data);
        assert_eq!(first_data.len, full_len);

        let second_data = syscall!(client.read_file_chunk());
        assert_eq!(&second_data.data, &large_data2);
        assert_eq!(second_data.len, full_len);

        let third_data = syscall!(client.read_file_chunk());
        assert_eq!(&third_data.data, &more_data);
        assert_eq!(third_data.len, full_len);

        assert_eq!(
            try_syscall!(client.read_file_chunk()),
            Err(Error::MechanismNotAvailable)
        );

        let metadata =
            syscall!(client.entry_metadata(Location::Internal, PathBuf::from("test_file")))
                .metadata
                .unwrap();
        assert!(metadata.is_file());

        // ======== ABORTED CHUNKED WRITES ========
        syscall!(client.start_encrypted_chunked_write(
            Location::Internal,
            PathBuf::from("test_file"),
            key,
            Some(ByteArray::from([1; 8])),
            None
        ));

        syscall!(client.write_file_chunk(large_data.clone()));
        syscall!(client.write_file_chunk(large_data2.clone()));
        syscall!(client.abort_chunked_write());

        //  Old data is still there after abort
        syscall!(client.start_encrypted_chunked_read(
            Location::Internal,
            PathBuf::from("test_file"),
            key
        ));
        let first_data = syscall!(client.read_file_chunk());
        assert_eq!(&first_data.data, &large_data);
        assert_eq!(first_data.len, full_len);

        let second_data = syscall!(client.read_file_chunk());
        assert_eq!(&second_data.data, &large_data2);
        assert_eq!(second_data.len, full_len);

        let third_data = syscall!(client.read_file_chunk());
        assert_eq!(&third_data.data, &more_data);
        assert_eq!(third_data.len, full_len);

        assert_eq!(
            try_syscall!(client.read_file_chunk()),
            Err(Error::MechanismNotAvailable)
        );

        // This returns an error because the name doesn't exist
        assert!(
            try_syscall!(client.remove_file(Location::Internal, PathBuf::from("bad_name")))
                .is_err()
        );
        let metadata =
            syscall!(client.entry_metadata(Location::Internal, PathBuf::from("test_file")))
                .metadata
                .unwrap();
        assert!(metadata.is_file());

        syscall!(client.remove_file(Location::Internal, PathBuf::from("test_file")));
        assert!(
            syscall!(client.entry_metadata(Location::Internal, PathBuf::from("test_file")))
                .metadata
                .is_none(),
        );
    })
}
