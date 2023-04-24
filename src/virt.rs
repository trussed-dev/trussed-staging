// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Wrapper around [`trussed::virt`][] that provides clients with both the core backend and the [`StagingBackend`](crate::StagingBackend) backend.

#[cfg(feature = "wrap-key-to-file")]
use crate::wrap_key_to_file::WrapKeyToFileExtension;

use crate::{StagingBackend, StagingContext};

#[derive(Default, Debug)]
pub struct Dispatcher {
    backend: StagingBackend,
}

#[derive(Debug)]
pub enum BackendIds {
    StagingBackend,
}

#[derive(Debug)]
pub enum ExtensionIds {
    #[cfg(feature = "wrap-key-to-file")]
    WrapKeyToFile,
}

#[cfg(feature = "wrap-key-to-file")]
impl ExtensionId<WrapKeyToFileExtension> for Dispatcher {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::WrapKeyToFile;
}

impl From<ExtensionIds> for u8 {
    fn from(value: ExtensionIds) -> Self {
        match value {
            #[cfg(feature = "wrap-key-to-file")]
            ExtensionIds::WrapKeyToFile => 0,
        }
    }
}

impl TryFrom<u8> for ExtensionIds {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            #[cfg(feature = "wrap-key-to-file")]
            0 => Ok(Self::WrapKeyToFile),
            _ => Err(Error::FunctionNotSupported),
        }
    }
}

impl ExtensionDispatch for Dispatcher {
    type BackendId = BackendIds;
    type Context = StagingContext;
    type ExtensionId = ExtensionIds;
    fn core_request<P: Platform>(
        &mut self,
        _backend: &Self::BackendId,
        ctx: &mut trussed::types::Context<Self::Context>,
        request: &trussed::api::Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, Error> {
        self.backend
            .request(&mut ctx.core, &mut ctx.backends, request, resources)
    }

    fn extension_request<P: Platform>(
        &mut self,
        _backend: &Self::BackendId,
        extension: &Self::ExtensionId,
        ctx: &mut trussed::types::Context<Self::Context>,
        request: &trussed::api::request::SerdeExtension,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::api::reply::SerdeExtension, Error> {
        let _ = &extension;
        let _ = &ctx;
        let _ = &request;
        let _ = &resources;
        // Dereference to avoid compile issue when all features are disabled requiring a default branch
        // See https://github.com/rust-lang/rust/issues/78123#
        match *extension {
            #[cfg(feature = "wrap-key-to-file")]
            ExtensionIds::WrapKeyToFile => self.backend.extension_request_serialized(
                &mut ctx.core,
                &mut ctx.backends,
                request,
                resources,
            ),
        }
    }
}

use std::path::PathBuf;
use trussed::{
    backend::{Backend, BackendId},
    serde_extensions::*,
    virt::{self, Filesystem, Ram, StoreProvider},
    Error, Platform,
};

pub type Client<S, D = Dispatcher> = virt::Client<S, D>;

pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
where
    F: FnOnce(Client<S>) -> R,
    S: StoreProvider,
{
    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            Dispatcher::default(),
            &[
                BackendId::Custom(BackendIds::StagingBackend),
                BackendId::Core,
            ],
            f,
        )
    })
}

pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Filesystem>) -> R,
    P: Into<PathBuf>,
{
    with_client(Filesystem::new(internal), client_id, f)
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Ram>) -> R,
{
    with_client(Ram::default(), client_id, f)
}
