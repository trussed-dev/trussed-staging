// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use littlefs2::{
    fs::DirEntry,
    object_safe::DynFilesystem,
    path,
    path::{Path, PathBuf},
};
use serde::{Deserialize, Serialize};
use trussed::{
    serde_extensions::{Extension, ExtensionClient, ExtensionImpl, ExtensionResult},
    store::Store,
    types::Location,
    Error,
};

#[derive(Debug)]
pub struct Migrator {
    /// The function performing the migration
    ///
    /// First argument is the Internal Filesystem, second argument is the External
    pub migrate: fn(&dyn DynFilesystem, &dyn DynFilesystem) -> Result<(), littlefs2::io::Error>,

    /// The version of the storage for which the migration needs to be run
    pub version: u32,
}

use crate::StagingBackend;

pub struct ManageExtension;

/// Factory reset the entire device
///
/// This will reset all filesystems
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct FactoryResetDeviceRequest;

/// Factory reset a specific application
///
/// This will reset all data for a specific client
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FactoryResetClientRequest {
    pub client: PathBuf,
}

/// Request a migration of the filesystem
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct MigrateRequest {
    /// Run migrators where [`version`](Migrator::version) is larger than `from_version`
    pub from_version: u32,
    /// Run migrators where [`version`](Migrator::version) is lower or equal to `to_version`
    pub to_version: u32,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum ManageRequest {
    FactoryResetDevice(FactoryResetDeviceRequest),
    FactoryResetClient(FactoryResetClientRequest),
    Migrate(MigrateRequest),
}

impl From<FactoryResetClientRequest> for ManageRequest {
    fn from(value: FactoryResetClientRequest) -> Self {
        Self::FactoryResetClient(value)
    }
}

impl TryFrom<ManageRequest> for FactoryResetClientRequest {
    type Error = Error;
    fn try_from(value: ManageRequest) -> Result<Self, Self::Error> {
        match value {
            ManageRequest::FactoryResetClient(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<FactoryResetDeviceRequest> for ManageRequest {
    fn from(value: FactoryResetDeviceRequest) -> Self {
        Self::FactoryResetDevice(value)
    }
}

impl TryFrom<ManageRequest> for FactoryResetDeviceRequest {
    type Error = Error;
    fn try_from(value: ManageRequest) -> Result<Self, Self::Error> {
        match value {
            ManageRequest::FactoryResetDevice(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<MigrateRequest> for ManageRequest {
    fn from(value: MigrateRequest) -> Self {
        Self::Migrate(value)
    }
}

impl TryFrom<ManageRequest> for MigrateRequest {
    type Error = Error;
    fn try_from(value: ManageRequest) -> Result<Self, Self::Error> {
        match value {
            ManageRequest::Migrate(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

/// Factory reset the entire device
///
/// This will reset all filesystems
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct FactoryResetDeviceReply;

/// Factory reset a specific application
///
/// This will reset all data for a specific client
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FactoryResetClientReply;

/// Request a migration of the filesystem
#[derive(Debug, Deserialize, Serialize, Copy, Clone)]
pub struct MigrateReply;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum ManageReply {
    FactoryResetDevice(FactoryResetDeviceReply),
    FactoryResetClient(FactoryResetClientReply),
    Migrate(MigrateReply),
}

impl From<FactoryResetClientReply> for ManageReply {
    fn from(value: FactoryResetClientReply) -> Self {
        Self::FactoryResetClient(value)
    }
}

impl TryFrom<ManageReply> for FactoryResetClientReply {
    type Error = Error;
    fn try_from(value: ManageReply) -> Result<Self, Self::Error> {
        match value {
            ManageReply::FactoryResetClient(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<FactoryResetDeviceReply> for ManageReply {
    fn from(value: FactoryResetDeviceReply) -> Self {
        Self::FactoryResetDevice(value)
    }
}

impl TryFrom<ManageReply> for FactoryResetDeviceReply {
    type Error = Error;
    fn try_from(value: ManageReply) -> Result<Self, Self::Error> {
        match value {
            ManageReply::FactoryResetDevice(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl From<MigrateReply> for ManageReply {
    fn from(value: MigrateReply) -> Self {
        Self::Migrate(value)
    }
}

impl TryFrom<ManageReply> for MigrateReply {
    type Error = Error;
    fn try_from(value: ManageReply) -> Result<Self, Self::Error> {
        match value {
            ManageReply::Migrate(v) => Ok(v),
            _ => Err(Error::InternalError),
        }
    }
}

impl Extension for ManageExtension {
    type Request = ManageRequest;
    type Reply = ManageReply;
}

type ManageResult<'a, R, C> = ExtensionResult<'a, ManageExtension, R, C>;

pub trait ManageClient: ExtensionClient<ManageExtension> {
    /// Factory reset the entire device
    ///
    /// This will reset all filesystems
    fn factory_reset_device(&mut self) -> ManageResult<'_, FactoryResetDeviceReply, Self> {
        self.extension(FactoryResetDeviceRequest)
    }

    /// Factory reset the entire client
    ///
    fn factory_reset_client(
        &mut self,
        client: &Path,
    ) -> ManageResult<'_, FactoryResetClientReply, Self> {
        self.extension(FactoryResetClientRequest {
            client: client.into(),
        })
    }

    /// Perform the migrations configured in [`State::migrators`]
    ///
    /// Run the migrators where [`version`](Migrator::version) is larger than `from_version` and lower than `to_version`
    fn migrate(
        &mut self,
        from_version: u32,
        to_version: u32,
    ) -> ManageResult<'_, MigrateReply, Self> {
        self.extension(MigrateRequest {
            from_version,
            to_version,
        })
    }
}

#[derive(Debug, Clone)]
pub struct State {
    /// Function called during a factory reset (of a client or the whole device)
    ///
    /// The path start all  start with the root. Here is an example such function:
    /// ```rust
    ///# use trussed::types::{Path, Location};
    ///# use littlefs2::path;
    /// fn should_preserve(path: &Path, location: Location) -> bool {
    ///     (location == Location::Internal && path == path!("/client1/dat/to_save_internal"))
    ///         || (location == Location::External && path == path!("/client1/dat/to_save_external"))
    ///         || (location == Location::Volatile && path == path!("/client1/dat/to_save_volatile"))
    /// }
    /// ```
    pub should_preserve_file: fn(&Path, location: Location) -> bool,

    pub migrators: &'static [Migrator],
}

impl Default for State {
    fn default() -> State {
        State {
            should_preserve_file: |_, _| false,
            migrators: &[],
        }
    }
}

fn callback(
    should_preserve_file: fn(&Path, location: Location) -> bool,
    location: Location,
) -> impl Fn(&DirEntry) -> bool {
    move |f| !should_preserve_file(f.path(), location)
}

impl<C: ExtensionClient<ManageExtension>> ManageClient for C {}

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
            ManageRequest::Migrate(MigrateRequest {
                from_version,
                to_version,
            }) => {
                let platform = resources.platform();
                let store = platform.store();
                let internal = store.ifs();
                let external = store.efs();
                for migration in self.manage.migrators {
                    if migration.version > *from_version && migration.version <= *to_version {
                        (migration.migrate)(&**internal, &**external).map_err(|_err| {
                            error_now!("Migration failed: {_err:?}");
                            Error::FilesystemWriteFailure
                        })?;
                    }
                }
                Ok(ManageReply::Migrate(MigrateReply))
            }
        }
    }
}
