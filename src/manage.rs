// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use littlefs2_core::{path, DirEntry, Path};
use trussed::{
    serde_extensions::{Extension, ExtensionImpl},
    store::Store,
    types::Location,
    Error,
};
use trussed_manage::{
    FactoryResetClientReply, FactoryResetClientRequest, FactoryResetDeviceReply,
    FactoryResetDeviceRequest, ManageExtension, ManageReply, ManageRequest,
};

use crate::StagingBackend;

#[derive(Debug, Clone)]
pub struct State {
    /// Function called during a factory reset (of a client or the whole device)
    ///
    /// The path start all  start with the root. Here is an example such function:
    /// ```rust
    ///# use trussed::types::{Path, Location};
    ///# use littlefs2_core::path;
    /// fn should_preserve(path: &Path, location: Location) -> bool {
    ///     (location == Location::Internal && path == path!("/client1/dat/to_save_internal"))
    ///         || (location == Location::External && path == path!("/client1/dat/to_save_external"))
    ///         || (location == Location::Volatile && path == path!("/client1/dat/to_save_volatile"))
    /// }
    /// ```
    pub should_preserve_file: fn(&Path, location: Location) -> bool,
}

impl Default for State {
    fn default() -> State {
        State {
            should_preserve_file: |_, _| false,
        }
    }
}

fn callback(
    should_preserve_file: fn(&Path, location: Location) -> bool,
    location: Location,
) -> impl Fn(&DirEntry) -> bool {
    move |f| !should_preserve_file(f.path(), location)
}

impl ExtensionImpl<ManageExtension> for StagingBackend {
    fn extension_request<P: trussed::Platform>(
        &mut self,
        _core_ctx: &mut trussed::types::CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &<ManageExtension as Extension>::Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<<ManageExtension as Extension>::Reply, Error> {
        match request {
            ManageRequest::FactoryResetDevice(FactoryResetDeviceRequest) => {
                let platform = resources.platform();
                let store = platform.store();

                for location in [Location::Internal, Location::External, Location::Volatile] {
                    store
                        .fs(location)
                        .remove_dir_all_where(
                            path!("/"),
                            &callback(self.manage.should_preserve_file, location),
                        )
                        .map_err(|_err| {
                            debug!("Failed to delete {location:?} fs: {_err:?}");
                            Error::FunctionFailed
                        })?;
                }
                Ok(ManageReply::FactoryResetDevice(FactoryResetDeviceReply))
            }
            ManageRequest::FactoryResetClient(FactoryResetClientRequest { client }) => {
                let platform = resources.platform();
                let store = platform.store();

                if client.parent().is_some() {
                    return Err(Error::InvalidPath);
                }

                let path = path!("/").join(client);

                for location in [Location::Internal, Location::External, Location::Volatile] {
                    store
                        .fs(location)
                        .remove_dir_all_where(
                            &path,
                            &callback(self.manage.should_preserve_file, location),
                        )
                        .map_err(|_err| {
                            debug!("Failed to delete {location:?} fs: {_err:?}");
                            Error::FunctionFailed
                        })?;
                }
                Ok(ManageReply::FactoryResetClient(FactoryResetClientReply))
            }
        }
    }
}
