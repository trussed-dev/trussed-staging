// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Wrapper around [`trussed::virt`][] that provides clients with both the core backend and the [`StagingBackend`] backend.

#[cfg(feature = "manage")]
use trussed::types::{Location, Path};

#[cfg(feature = "chunked")]
use trussed_chunked::ChunkedExtension;
#[cfg(feature = "fs-info")]
use trussed_fs_info::FsInfoExtension;
#[cfg(feature = "hkdf")]
use trussed_hkdf::HkdfExtension;
#[cfg(feature = "hpke")]
use trussed_hpke::HpkeExtension;
#[cfg(feature = "manage")]
use trussed_manage::ManageExtension;
#[cfg(feature = "wrap-key-to-file")]
use trussed_wrap_key_to_file::WrapKeyToFileExtension;

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
    #[cfg(feature = "chunked")]
    Chunked,
    #[cfg(feature = "hkdf")]
    Hkdf,
    #[cfg(feature = "manage")]
    Manage,
    #[cfg(feature = "wrap-key-to-file")]
    WrapKeyToFile,
    #[cfg(feature = "fs-info")]
    FsInfo,
    #[cfg(feature = "hpke")]
    Hpke,
}

#[cfg(feature = "chunked")]
impl ExtensionId<ChunkedExtension> for Dispatcher {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::Chunked;
}

#[cfg(feature = "hkdf")]
impl ExtensionId<HkdfExtension> for Dispatcher {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::Hkdf;
}

#[cfg(feature = "manage")]
impl ExtensionId<ManageExtension> for Dispatcher {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::Manage;
}

#[cfg(feature = "wrap-key-to-file")]
impl ExtensionId<WrapKeyToFileExtension> for Dispatcher {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::WrapKeyToFile;
}

#[cfg(feature = "fs-info")]
impl ExtensionId<FsInfoExtension> for Dispatcher {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::FsInfo;
}

#[cfg(feature = "hpke")]
impl ExtensionId<HpkeExtension> for Dispatcher {
    type Id = ExtensionIds;
    const ID: ExtensionIds = ExtensionIds::Hpke;
}

impl From<ExtensionIds> for u8 {
    fn from(value: ExtensionIds) -> Self {
        match value {
            #[cfg(feature = "chunked")]
            ExtensionIds::Chunked => 0,
            #[cfg(feature = "hkdf")]
            ExtensionIds::Hkdf => 1,
            #[cfg(feature = "manage")]
            ExtensionIds::Manage => 2,
            #[cfg(feature = "wrap-key-to-file")]
            ExtensionIds::WrapKeyToFile => 3,
            #[cfg(feature = "fs-info")]
            ExtensionIds::FsInfo => 4,
            #[cfg(feature = "hpke")]
            ExtensionIds::Hpke => 5,
        }
    }
}

impl TryFrom<u8> for ExtensionIds {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            #[cfg(feature = "chunked")]
            0 => Ok(Self::Chunked),
            #[cfg(feature = "hkdf")]
            1 => Ok(Self::Hkdf),
            #[cfg(feature = "manage")]
            2 => Ok(Self::Manage),
            #[cfg(feature = "wrap-key-to-file")]
            3 => Ok(Self::WrapKeyToFile),
            #[cfg(feature = "fs-info")]
            4 => Ok(Self::FsInfo),
            #[cfg(feature = "hpke")]
            5 => Ok(Self::Hpke),
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
            ExtensionIds::WrapKeyToFile => {
                ExtensionImpl::<WrapKeyToFileExtension>::extension_request_serialized(
                    &mut self.backend,
                    &mut ctx.core,
                    &mut ctx.backends,
                    request,
                    resources,
                )
            }

            #[cfg(feature = "chunked")]
            ExtensionIds::Chunked => {
                ExtensionImpl::<ChunkedExtension>::extension_request_serialized(
                    &mut self.backend,
                    &mut ctx.core,
                    &mut ctx.backends,
                    request,
                    resources,
                )
            }

            #[cfg(feature = "hkdf")]
            ExtensionIds::Hkdf => ExtensionImpl::<HkdfExtension>::extension_request_serialized(
                &mut self.backend,
                &mut ctx.core,
                &mut ctx.backends,
                request,
                resources,
            ),

            #[cfg(feature = "manage")]
            ExtensionIds::Manage => ExtensionImpl::<ManageExtension>::extension_request_serialized(
                &mut self.backend,
                &mut ctx.core,
                &mut ctx.backends,
                request,
                resources,
            ),
            #[cfg(feature = "fs-info")]
            ExtensionIds::FsInfo => ExtensionImpl::<FsInfoExtension>::extension_request_serialized(
                &mut self.backend,
                &mut ctx.core,
                &mut ctx.backends,
                request,
                resources,
            ),
            #[cfg(feature = "hpke")]
            ExtensionIds::Hpke => ExtensionImpl::<HpkeExtension>::extension_request_serialized(
                &mut self.backend,
                &mut ctx.core,
                &mut ctx.backends,
                request,
                resources,
            ),
        }
    }
}

use trussed::{
    backend::{Backend, BackendId},
    serde_extensions::*,
    virt::{self, StoreConfig},
    Error, Platform,
};

pub type Client<'a, D = Dispatcher> = virt::Client<'a, D>;

pub fn with_client<R, F>(store: StoreConfig, client_id: &str, f: F) -> R
where
    F: FnOnce(Client) -> R,
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

#[cfg(feature = "manage")]
pub fn with_client_and_preserve<R, F>(
    store: StoreConfig,
    client_id: &str,
    f: F,
    should_preserve_file: fn(&Path, location: Location) -> bool,
) -> R
where
    F: FnOnce(Client) -> R,
{
    let mut dispatcher = Dispatcher::default();
    dispatcher.backend.manage.should_preserve_file = should_preserve_file;

    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            dispatcher,
            &[
                BackendId::Custom(BackendIds::StagingBackend),
                BackendId::Core,
            ],
            f,
        )
    })
}

#[cfg(feature = "manage")]
pub fn with_clients_and_preserve<R, F, const N: usize>(
    store: StoreConfig,
    client_ids: [&str; N],
    should_preserve_file: fn(&Path, location: Location) -> bool,
    f: F,
) -> R
where
    F: FnOnce([Client; N]) -> R,
{
    let mut dispatcher = Dispatcher::default();
    dispatcher.backend.manage.should_preserve_file = should_preserve_file;
    let clients_backend = client_ids.map(|id| {
        (
            id,
            [
                BackendId::Custom(BackendIds::StagingBackend),
                BackendId::Core,
            ]
            .as_slice(),
        )
    });

    virt::with_platform(store, |platform| {
        platform.run_clients_with_backends(clients_backend, dispatcher, f)
    })
}
