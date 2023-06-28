// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(all(feature = "virt", feature = "hmacsha256p256"))]

use trussed::client::CryptoClient;
use trussed::key::Kind;
use trussed::syscall;
use trussed::types::{Location::*, Mechanism, SignatureSerialization};

use trussed::types::Location;

use trussed_staging::virt::with_ram_client;

use trussed::client::P256;
use trussed_staging::hmacsha256p256::HmacSha256P256Client;

#[test]
fn hmac_inject_any() {
    with_ram_client("staging-tests", |mut client| {
        let client = &mut client;

        let key = syscall!(client.inject_any_key(
            b"12345678123456781234567812345678",
            Volatile,
            Kind::P256
        ))
        .key
        .unwrap();

        let pk = syscall!(client.derive_p256_public_key(key, Location::Volatile)).key;

        let signature =
            syscall!(client.sign(Mechanism::P256, key, &[], SignatureSerialization::Raw)).signature;
        assert!(signature.len() > 0);
        todo!();
    });
}
