use littlefs2::path;
use littlefs2::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use trussed::{
    serde_extensions::{Extension, ExtensionClient, ExtensionImpl, ExtensionResult},
    store::Store,
    Error,
};

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
    client: PathBuf,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum ManageRequest {
    FactoryResetDevice(FactoryResetDeviceRequest),
    FactoryResetClient(FactoryResetClientRequest),
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum ManageReply {
    FactoryResetDevice(FactoryResetDeviceReply),
    FactoryResetClient(FactoryResetClientReply),
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
}

#[derive(Default, Debug, Clone)]
pub struct State {
    pub ifs_to_preserve: &'static [&'static Path],
    pub efs_to_preserve: &'static [&'static Path],
    pub vfs_to_preserve: &'static [&'static Path],
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
                let ifs = store.ifs();
                let efs = store.efs();
                let vfs = store.vfs();
                ifs.remove_dir_all_where(path!("/"), &|f| {
                    let file_name = f.file_name();
                    if self.manage.ifs_to_preserve.contains(&file_name) {
                        return false;
                    }
                    true
                })
                .map_err(|_err| {
                    debug!("Failed to delete ifs: {_err:?}");
                    Error::FunctionFailed
                })?;
                efs.remove_dir_all_where(path!("/"), &|f| {
                    let file_name = f.file_name();
                    if self.manage.efs_to_preserve.contains(&file_name) {
                        return false;
                    }
                    true
                })
                .map_err(|_err| {
                    debug!("Failed to delete efs: {_err:?}");
                    Error::FunctionFailed
                })?;
                vfs.remove_dir_all_where(path!("/"), &|f| {
                    let file_name = f.file_name();
                    if self.manage.vfs_to_preserve.contains(&file_name) {
                        return false;
                    }
                    true
                })
                .map_err(|_err| {
                    debug!("Failed to delete vfs: {_err:?}");
                    Error::FunctionFailed
                })?;
                Ok(ManageReply::FactoryResetDevice(FactoryResetDeviceReply))
            }
            ManageRequest::FactoryResetClient(FactoryResetClientRequest { client }) => {
                let platform = resources.platform();
                let store = platform.store();
                let ifs = store.ifs();
                let efs = store.efs();
                let vfs = store.vfs();
                ifs.remove_dir_all_where(client, &|f| {
                    let file_name = f.file_name();
                    if self.manage.ifs_to_preserve.contains(&file_name) {
                        return false;
                    }
                    true
                })
                .map_err(|_err| {
                    debug!("Failed to delete ifs: {_err:?}");
                    Error::FunctionFailed
                })?;
                efs.remove_dir_all_where(client, &|f| {
                    let file_name = f.file_name();
                    if self.manage.efs_to_preserve.contains(&file_name) {
                        return false;
                    }
                    true
                })
                .map_err(|_err| {
                    debug!("Failed to delete efs: {_err:?}");
                    Error::FunctionFailed
                })?;
                vfs.remove_dir_all_where(client, &|f| {
                    let file_name = f.file_name();
                    if self.manage.vfs_to_preserve.contains(&file_name) {
                        return false;
                    }
                    true
                })
                .map_err(|_err| {
                    debug!("Failed to delete vfs: {_err:?}");
                    Error::FunctionFailed
                })?;
                Ok(ManageReply::FactoryResetClient(FactoryResetClientReply))
            }
        }
    }
}
