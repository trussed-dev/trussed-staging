// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(all(feature = "virt", feature = "manage"))]

use littlefs2_core::path;
use trussed::client::FilesystemClient;
use trussed::syscall;
use trussed::types::{Bytes, Location, Path};
use trussed::virt::StoreConfig;
use trussed_manage::ManageClient;
use trussed_staging::virt::with_clients_and_preserve;

fn should_preserve(path: &Path, location: Location) -> bool {
    (location == Location::Internal && path == path!("/client1/dat/to_save_internal"))
        || (location == Location::External && path == path!("/client1/dat/to_save_external"))
        || (location == Location::Volatile && path == path!("/client1/dat/to_save_volatile"))
}

#[test]
fn device_factory_reset() {
    with_clients_and_preserve(
        StoreConfig::ram(),
        ["client1", "client2"],
        should_preserve,
        |[mut client1, mut client2]| {
            syscall!(client1.write_file(
                Location::Internal,
                path!("to_save_internal").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client1.write_file(
                Location::External,
                path!("to_save_external").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client1.write_file(
                Location::Volatile,
                path!("to_save_volatile").into(),
                Bytes::from_slice(b"data").unwrap(),
                None
            ));
            syscall!(client1.write_file(
                Location::Internal,
                path!("to_delete_internal").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client1.write_file(
                Location::External,
                path!("to_delete_external").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client1.write_file(
                Location::Volatile,
                path!("to_delete_volatile").into(),
                Bytes::from_slice(b"data").unwrap(),
                None
            ));

            syscall!(client2.write_file(
                Location::Internal,
                path!("to_delete_internal").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client2.write_file(
                Location::External,
                path!("to_delete_external").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client2.write_file(
                Location::Volatile,
                path!("to_delete_volatile").into(),
                Bytes::from_slice(b"data").unwrap(),
                None
            ));

            syscall!(client1.factory_reset_device());
            assert!(syscall!(
                client1.entry_metadata(Location::Internal, path!("to_save_internal").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client1.entry_metadata(Location::External, path!("to_save_external").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client1.entry_metadata(Location::Volatile, path!("to_save_volatile").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client1.entry_metadata(Location::Internal, path!("to_delete_internal").into())
            )
            .metadata
            .is_none());
            assert!(syscall!(
                client1.entry_metadata(Location::External, path!("to_delete_external").into())
            )
            .metadata
            .is_none());
            assert!(syscall!(
                client1.entry_metadata(Location::Volatile, path!("to_delete_volatile").into())
            )
            .metadata
            .is_none());
            assert!(syscall!(
                client2.entry_metadata(Location::Internal, path!("to_delete_internal").into())
            )
            .metadata
            .is_none());
            assert!(syscall!(
                client2.entry_metadata(Location::External, path!("to_delete_external").into())
            )
            .metadata
            .is_none());
            assert!(syscall!(
                client2.entry_metadata(Location::Volatile, path!("to_delete_volatile").into())
            )
            .metadata
            .is_none());
        },
    );
}

#[test]
fn client_factory_reset() {
    with_clients_and_preserve(
        StoreConfig::ram(),
        ["client1", "client2"],
        should_preserve,
        |[mut client1, mut client2]| {
            syscall!(client1.write_file(
                Location::Internal,
                path!("to_save_internal").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client1.write_file(
                Location::External,
                path!("to_save_external").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client1.write_file(
                Location::Volatile,
                path!("to_save_volatile").into(),
                Bytes::from_slice(b"data").unwrap(),
                None
            ));
            syscall!(client2.write_file(
                Location::Internal,
                path!("to_delete_internal").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client2.write_file(
                Location::External,
                path!("to_delete_external").into(),
                Bytes::from_slice(b"data").unwrap(),
                None,
            ));
            syscall!(client2.write_file(
                Location::Volatile,
                path!("to_delete_volatile").into(),
                Bytes::from_slice(b"data").unwrap(),
                None
            ));

            syscall!(client1.factory_reset_client(path!("client1")));
            assert!(syscall!(
                client1.entry_metadata(Location::Internal, path!("to_save_internal").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client1.entry_metadata(Location::External, path!("to_save_external").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client1.entry_metadata(Location::Volatile, path!("to_save_volatile").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client1.entry_metadata(Location::Internal, path!("to_delete_internal").into())
            )
            .metadata
            .is_none());
            assert!(syscall!(
                client1.entry_metadata(Location::External, path!("to_delete_external").into())
            )
            .metadata
            .is_none());
            assert!(syscall!(
                client1.entry_metadata(Location::Volatile, path!("to_delete_volatile").into())
            )
            .metadata
            .is_none());

            // DATA for other clients is still there
            assert!(syscall!(
                client2.entry_metadata(Location::Internal, path!("to_delete_internal").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client2.entry_metadata(Location::External, path!("to_delete_external").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client2.entry_metadata(Location::Volatile, path!("to_delete_volatile").into())
            )
            .metadata
            .is_some());

            syscall!(client1.factory_reset_client(path!("client2")));
            assert!(syscall!(
                client1.entry_metadata(Location::Internal, path!("to_save_internal").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client1.entry_metadata(Location::External, path!("to_save_external").into())
            )
            .metadata
            .is_some());
            assert!(syscall!(
                client1.entry_metadata(Location::Volatile, path!("to_save_volatile").into())
            )
            .metadata
            .is_some());

            // DATA for other clients is deleted
            assert!(syscall!(
                client2.entry_metadata(Location::Internal, path!("to_delete_internal").into())
            )
            .metadata
            .is_none());
            assert!(syscall!(
                client2.entry_metadata(Location::External, path!("to_delete_external").into())
            )
            .metadata
            .is_none());
            assert!(syscall!(
                client2.entry_metadata(Location::Volatile, path!("to_delete_volatile").into())
            )
            .metadata
            .is_none());
        },
    );
}
