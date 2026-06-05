// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

use trussed::{
    serde_extensions::ExtensionImpl, service::ServiceResources, store::Store, types::CoreContext,
    Platform,
};
use trussed_core::Error;
use trussed_fs_info::{
    BlockInfo, FsInfoExtension, FsInfoExtensionReply, FsInfoExtensionRequest, FsInfoReply,
};

impl ExtensionImpl<FsInfoExtension> for super::StagingBackend {
    fn extension_request<P: Platform>(
        &mut self,
        _core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &FsInfoExtensionRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<FsInfoExtensionReply, Error> {
        match request {
            FsInfoExtensionRequest::FsInfo(req) => {
                let platform = resources.platform();
                let store = platform.store();
                let fs = store.fs(req.location);
                Ok(FsInfoReply {
                    block_info: Some(BlockInfo {
                        total: fs.total_blocks(),
                        available: fs.available_blocks().map_err(|_| Error::InternalError)?,
                        size: fs.total_space() / fs.total_blocks(),
                    }),
                    available_space: fs.available_space().map_err(|_| Error::InternalError)?,
                }
                .into())
            }
        }
    }
}
