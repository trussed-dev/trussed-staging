// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![warn(
    missing_debug_implementations,
    // missing_docs,
    non_ascii_idents,
    trivial_casts,
    unused,
    unused_qualifications
)]
#![deny(unsafe_code)]

delog::generate_macros!();

use trussed::backend::Backend;

#[cfg(feature = "virt")]
pub mod virt;

#[cfg(feature = "chacha20poly1305")]
pub mod wrap_key_to_file;

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct StagingBackend {}

impl StagingBackend {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Default, Debug)]
#[non_exhaustive]
pub struct StagingContext {}

impl Backend for StagingBackend {
    type Context = StagingContext;
}
