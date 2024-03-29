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
mod wrap_key_to_file;

#[cfg(feature = "fs-info")]
mod fs_info;

#[cfg(feature = "chunked")]
mod chunked;

#[cfg(feature = "hkdf")]
mod hkdf;

#[cfg(feature = "hpke")]
mod hpke;

#[cfg(feature = "manage")]
mod manage;
#[cfg(feature = "manage")]
pub use manage::State as ManageState;

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct StagingBackend {
    #[cfg(feature = "manage")]
    pub manage: ManageState,
}

impl StagingBackend {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "manage")]
            manage: Default::default(),
        }
    }
}

#[derive(Default)]
#[non_exhaustive]
pub struct StagingContext {
    #[cfg(feature = "chunked")]
    chunked_io_state: Option<chunked::ChunkedIoState>,
}

impl Backend for StagingBackend {
    type Context = StagingContext;
}
