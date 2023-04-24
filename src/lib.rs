// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

delog::generate_macros!();

use trussed::backend::Backend;

#[cfg(feature = "virt")]
pub mod virt;

#[cfg(feature = "wrap-key-to-file")]
pub mod wrap_key_to_file;

#[cfg(feature = "chunked")]
pub mod streaming;

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct StagingBackend {}

impl StagingBackend {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Default)]
#[non_exhaustive]
pub struct StagingContext {
    #[cfg(feature = "chunked")]
    chunked_io_state: Option<streaming::ChunkedIoState>,
}

impl Backend for StagingBackend {
    type Context = StagingContext;
}
