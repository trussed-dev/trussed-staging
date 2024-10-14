// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(all(feature = "virt", feature = "hpke"))]

use littlefs2_core::path;
use trussed::client::{CryptoClient, X255};
use trussed::{
    syscall,
    types::{Bytes, KeyId, Location, Mechanism, SignatureSerialization},
};

use trussed_hpke::HpkeClient;

use trussed_staging::virt;

fn assert_symkey_eq<C: trussed::Client>(this: KeyId, other: KeyId, client: &mut C) {
    let hmac_this = syscall!(client.sign(
        Mechanism::HmacSha256,
        this,
        b"DATA",
        SignatureSerialization::Raw
    ))
    .signature;
    let hmac_other = syscall!(client.sign(
        Mechanism::HmacSha256,
        other,
        b"DATA",
        SignatureSerialization::Raw
    ))
    .signature;

    assert_eq!(hmac_other, hmac_this);
}

#[test]
fn hpke_message() {
    virt::with_ram_client("hpke_test_message", |mut client| {
        let secret_key = syscall!(client.generate_x255_secret_key(Location::Volatile)).key;
        let public_key =
            syscall!(client.derive_x255_public_key(secret_key, Location::Volatile)).key;

        let pl = Bytes::from_slice(b"Plaintext").unwrap();
        let aad = Bytes::from_slice(b"AAD").unwrap();
        let info = Bytes::from_slice(b"INFO").unwrap();
        let seal = syscall!(client.hpke_seal(
            public_key,
            pl.clone(),
            aad.clone(),
            info.clone(),
            Location::Volatile
        ));

        assert!(seal.ciphertext != b"Plaintext");

        let opened =
            syscall!(client.hpke_open(secret_key, seal.enc, seal.ciphertext, seal.tag, aad, info));
        assert_eq!(opened.plaintext, pl);
    })
}

#[test]
fn hpke_wrap_key() {
    virt::with_ram_client("hpke_test_wrap_key", |mut client| {
        let secret_key = syscall!(client.generate_x255_secret_key(Location::Volatile)).key;
        let public_key =
            syscall!(client.derive_x255_public_key(secret_key, Location::Volatile)).key;

        let key_to_wrap = syscall!(client.generate_secret_key(32, Location::Volatile)).key;

        let aad = Bytes::from_slice(b"AAD").unwrap();
        let info = Bytes::from_slice(b"INFO").unwrap();
        let seal =
            syscall!(client.hpke_seal_key(public_key, key_to_wrap, aad.clone(), info.clone()));

        let unwrapped =
            syscall!(client.hpke_open_key(secret_key, seal.data, aad, info, Location::Volatile))
                .key;
        assert_ne!(unwrapped, key_to_wrap);

        assert_symkey_eq(key_to_wrap, unwrapped, &mut client);
    })
}

#[test]
fn hpke_wrap_key_to_file() {
    virt::with_ram_client("hpke_test_wrap_key_to_file", |mut client| {
        let secret_key = syscall!(client.generate_x255_secret_key(Location::Volatile)).key;
        let public_key =
            syscall!(client.derive_x255_public_key(secret_key, Location::Volatile)).key;

        let key_to_wrap = syscall!(client.generate_secret_key(32, Location::Volatile)).key;

        let path = path!("WRAPPED_KEY");
        let aad = Bytes::from_slice(b"AAD").unwrap();
        let info = Bytes::from_slice(b"INFO").unwrap();
        syscall!(client.hpke_seal_key_to_file(
            path.into(),
            Location::Volatile,
            public_key,
            key_to_wrap,
            aad.clone(),
            info.clone()
        ));

        let unwrapped = syscall!(client.hpke_open_key_from_file(
            secret_key,
            path.into(),
            Location::Volatile,
            Location::Volatile,
            aad,
            info
        ))
        .key;
        assert_ne!(unwrapped, key_to_wrap);

        assert_symkey_eq(key_to_wrap, unwrapped, &mut client);
    })
}
