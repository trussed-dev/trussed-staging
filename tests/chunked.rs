// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(all(feature = "virt", feature = "chunked"))]

use littlefs2::path::PathBuf;
use trussed::{client::FilesystemClient, syscall, try_syscall, types::Location, Bytes};
use trussed_staging::{
    streaming::{utils, ChunkedClient},
    virt::with_ram_client,
};
fn test_write_all(location: Location) {
    with_ram_client("test chunked", |mut client| {
        let path = PathBuf::from("foo");
        utils::write_all(&mut client, location, path.clone(), &[48; 1234], None, None).unwrap();

        let data = syscall!(client.start_chunked_read(location, path)).data;
        assert_eq!(&data, &[48; 1024]);
        let data = syscall!(client.read_file_chunk()).data;
        assert_eq!(&data, &[48; 1234 - 1024]);
    });
}

fn test_write_all_small(location: Location) {
    with_ram_client("test chunked", |mut client| {
        let path = PathBuf::from("foo2");
        utils::write_all(&mut client, location, path.clone(), &[48; 1023], None, None).unwrap();

        let data = syscall!(client.start_chunked_read(location, path)).data;
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
fn filesystem() {
    with_ram_client("chunked-tests", |mut client| {
        assert!(
            syscall!(client.entry_metadata(Location::Internal, PathBuf::from("test_file")))
                .metadata
                .is_none(),
        );

        let data = Bytes::from_slice(b"test data").unwrap();
        syscall!(client.write_file(
            Location::Internal,
            PathBuf::from("test_file"),
            data.clone(),
            None,
        ));

        let recv_data =
            syscall!(client.read_file(Location::Internal, PathBuf::from("test_file"))).data;
        assert_eq!(data, recv_data);

        // ======== CHUNKED READS ========
        let first_data =
            syscall!(client.start_chunked_read(Location::Internal, PathBuf::from("test_file"),));
        assert_eq!(&first_data.data, &data);
        assert_eq!(first_data.len, data.len());

        let empty_data = syscall!(client.read_file_chunk());
        assert!(empty_data.data.is_empty());
        assert_eq!(empty_data.len, data.len());

        let large_data = Bytes::from_slice(&[0; 1024]).unwrap();
        let large_data2 = Bytes::from_slice(&[1; 1024]).unwrap();
        let more_data = Bytes::from_slice(&[2; 42]).unwrap();
        // ======== CHUNKED WRITES ========
        syscall!(client.start_chunked_write(Location::Internal, PathBuf::from("test_file"), None));

        syscall!(client.write_file_chunk(large_data.clone()));
        syscall!(client.write_file_chunk(large_data2.clone()));
        syscall!(client.write_file_chunk(more_data.clone()));

        // ======== CHUNKED READS ========
        let full_len = large_data.len() + large_data2.len() + more_data.len();
        let first_data =
            syscall!(client.start_chunked_read(Location::Internal, PathBuf::from("test_file"),));
        assert_eq!(&first_data.data, &large_data);
        assert_eq!(first_data.len, full_len);

        let second_data = syscall!(client.read_file_chunk());
        assert_eq!(&second_data.data, &large_data2);
        assert_eq!(second_data.len, full_len);

        let third_data = syscall!(client.read_file_chunk());
        assert_eq!(&third_data.data, &more_data);
        assert_eq!(third_data.len, full_len);

        let empty_data = syscall!(client.read_file_chunk());
        assert!(empty_data.data.is_empty());
        assert_eq!(empty_data.len, full_len);

        let metadata =
            syscall!(client.entry_metadata(Location::Internal, PathBuf::from("test_file")))
                .metadata
                .unwrap();
        assert!(metadata.is_file());

        // ======== ABORTED CHUNKED WRITES ========
        syscall!(client.start_chunked_write(Location::Internal, PathBuf::from("test_file"), None));

        syscall!(client.write_file_chunk(large_data.clone()));
        syscall!(client.write_file_chunk(large_data2));
        syscall!(client.abort_chunked_write());

        //  Old data is still there after abort
        let partial_data =
            syscall!(client.start_chunked_read(Location::Internal, PathBuf::from("test_file")));
        assert_eq!(&partial_data.data, &large_data);
        assert_eq!(partial_data.len, full_len);

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
