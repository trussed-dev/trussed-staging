// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(non_ascii_idents, trivial_casts, unused, unused_qualifications)]
#![deny(unsafe_code)]

delog::generate_macros!();

use trussed::{backend::Backend, service::ServiceResources, types::CoreContext};
#[cfg(any(feature = "ml-dsa", feature = "ml-kem"))]
use trussed_core::types::Mechanism;
use trussed_core::{
    api::{Reply, Request},
    Error,
};

#[cfg(feature = "ml-dsa")]
mod ml_dsa_impl;
#[cfg(feature = "ml-dsa")]
use ml_dsa_impl::Params as _;

#[cfg(feature = "ml-kem")]
mod ml_kem_impl;
#[cfg(feature = "ml-kem")]
use ml_kem_impl::Params as _;

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

    fn request<P: trussed::Platform>(
        &mut self,
        _core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        _request: &Request,
        _resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        /// Coerce an FnMut into a FnOnce to ensure the stores are not created twice by mistake
        fn once<R, P>(
            generator: impl FnMut(&mut ServiceResources<P>, &mut CoreContext) -> R,
        ) -> impl FnOnce(&mut ServiceResources<P>, &mut CoreContext) -> R {
            generator
        }

        let _keystore = once(|resources: &mut ServiceResources<P>, core_ctx| {
            resources.keystore(core_ctx.path.clone())
        });

        #[cfg(feature = "ml-dsa")]
        match _request {
            Request::Sign(req) if req.mechanism == Mechanism::MlDsa44 => {
                return ml_dsa::MlDsa44
                    .sign(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Sign)
            }
            Request::Sign(req) if req.mechanism == Mechanism::MlDsa65 => {
                return ml_dsa::MlDsa65
                    .sign(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Sign)
            }
            Request::Sign(req) if req.mechanism == Mechanism::MlDsa87 => {
                return ml_dsa::MlDsa87
                    .sign(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Sign)
            }
            Request::DeriveKey(req) if req.mechanism == Mechanism::MlDsa44 => {
                return ml_dsa::MlDsa44
                    .derive_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeriveKey)
            }
            Request::DeriveKey(req) if req.mechanism == Mechanism::MlDsa65 => {
                return ml_dsa::MlDsa65
                    .derive_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeriveKey)
            }
            Request::DeriveKey(req) if req.mechanism == Mechanism::MlDsa87 => {
                return ml_dsa::MlDsa87
                    .derive_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeriveKey)
            }
            Request::DeserializeKey(req) if req.mechanism == Mechanism::MlDsa44 => {
                return ml_dsa::MlDsa44
                    .deserialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeserializeKey)
            }
            Request::DeserializeKey(req) if req.mechanism == Mechanism::MlDsa65 => {
                return ml_dsa::MlDsa65
                    .deserialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeserializeKey)
            }
            Request::DeserializeKey(req) if req.mechanism == Mechanism::MlDsa87 => {
                return ml_dsa::MlDsa87
                    .deserialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeserializeKey)
            }
            Request::GenerateKey(req) if req.mechanism == Mechanism::MlDsa44 => {
                return ml_dsa::MlDsa44
                    .generate_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::GenerateKey)
            }
            Request::GenerateKey(req) if req.mechanism == Mechanism::MlDsa65 => {
                return ml_dsa::MlDsa65
                    .generate_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::GenerateKey)
            }
            Request::GenerateKey(req) if req.mechanism == Mechanism::MlDsa87 => {
                return ml_dsa::MlDsa87
                    .generate_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::GenerateKey)
            }
            Request::SerializeKey(req) if req.mechanism == Mechanism::MlDsa44 => {
                return ml_dsa::MlDsa44
                    .serialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::SerializeKey)
            }
            Request::SerializeKey(req) if req.mechanism == Mechanism::MlDsa65 => {
                return ml_dsa::MlDsa65
                    .serialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::SerializeKey)
            }
            Request::SerializeKey(req) if req.mechanism == Mechanism::MlDsa87 => {
                return ml_dsa::MlDsa87
                    .serialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::SerializeKey)
            }
            Request::Exists(req) if req.mechanism == Mechanism::MlDsa44 => {
                return ml_dsa::MlDsa44
                    .exists(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Exists)
            }
            Request::Exists(req) if req.mechanism == Mechanism::MlDsa65 => {
                return ml_dsa::MlDsa65
                    .exists(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Exists)
            }
            Request::Exists(req) if req.mechanism == Mechanism::MlDsa87 => {
                return ml_dsa::MlDsa87
                    .exists(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Exists)
            }
            Request::Verify(req) if req.mechanism == Mechanism::MlDsa44 => {
                return ml_dsa::MlDsa44
                    .verify(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Verify)
            }
            Request::Verify(req) if req.mechanism == Mechanism::MlDsa65 => {
                return ml_dsa::MlDsa65
                    .verify(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Verify)
            }
            Request::Verify(req) if req.mechanism == Mechanism::MlDsa87 => {
                return ml_dsa::MlDsa87
                    .verify(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Verify)
            }
            Request::UnsafeInjectKey(req) if req.mechanism == Mechanism::MlDsa44 => {
                return ml_dsa::MlDsa44
                    .unsafe_inject_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::UnsafeInjectKey)
            }
            Request::UnsafeInjectKey(req) if req.mechanism == Mechanism::MlDsa65 => {
                return ml_dsa::MlDsa65
                    .unsafe_inject_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::UnsafeInjectKey)
            }
            Request::UnsafeInjectKey(req) if req.mechanism == Mechanism::MlDsa87 => {
                return ml_dsa::MlDsa87
                    .unsafe_inject_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::UnsafeInjectKey)
            }
            _ => {}
        }

        #[cfg(feature = "ml-kem")]
        match _request {
            Request::DeriveKey(req) if req.mechanism == Mechanism::MlKem512 => {
                return ml_kem::MlKem512
                    .derive_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeriveKey)
            }
            Request::DeriveKey(req) if req.mechanism == Mechanism::MlKem768 => {
                return ml_kem::MlKem768
                    .derive_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeriveKey)
            }
            Request::DeriveKey(req) if req.mechanism == Mechanism::MlKem1024 => {
                return ml_kem::MlKem1024
                    .derive_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeriveKey)
            }
            Request::DeserializeKey(req) if req.mechanism == Mechanism::MlKem512 => {
                return ml_kem::MlKem512
                    .deserialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeserializeKey)
            }
            Request::DeserializeKey(req) if req.mechanism == Mechanism::MlKem768 => {
                return ml_kem::MlKem768
                    .deserialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeserializeKey)
            }
            Request::DeserializeKey(req) if req.mechanism == Mechanism::MlKem1024 => {
                return ml_kem::MlKem1024
                    .deserialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::DeserializeKey)
            }
            Request::GenerateKey(req) if req.mechanism == Mechanism::MlKem512 => {
                return ml_kem::MlKem512
                    .generate_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::GenerateKey)
            }
            Request::GenerateKey(req) if req.mechanism == Mechanism::MlKem768 => {
                return ml_kem::MlKem768
                    .generate_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::GenerateKey)
            }
            Request::GenerateKey(req) if req.mechanism == Mechanism::MlKem1024 => {
                return ml_kem::MlKem1024
                    .generate_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::GenerateKey)
            }
            Request::SerializeKey(req) if req.mechanism == Mechanism::MlKem512 => {
                return ml_kem::MlKem512
                    .serialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::SerializeKey)
            }
            Request::SerializeKey(req) if req.mechanism == Mechanism::MlKem768 => {
                return ml_kem::MlKem768
                    .serialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::SerializeKey)
            }
            Request::SerializeKey(req) if req.mechanism == Mechanism::MlKem1024 => {
                return ml_kem::MlKem1024
                    .serialize_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::SerializeKey)
            }
            Request::Exists(req) if req.mechanism == Mechanism::MlKem512 => {
                return ml_kem::MlKem512
                    .exists(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Exists)
            }
            Request::Exists(req) if req.mechanism == Mechanism::MlKem768 => {
                return ml_kem::MlKem768
                    .exists(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Exists)
            }
            Request::Exists(req) if req.mechanism == Mechanism::MlKem1024 => {
                return ml_kem::MlKem1024
                    .exists(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::Exists)
            }
            Request::UnsafeInjectKey(req) if req.mechanism == Mechanism::MlKem512 => {
                return ml_kem::MlKem512
                    .unsafe_inject_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::UnsafeInjectKey)
            }
            Request::UnsafeInjectKey(req) if req.mechanism == Mechanism::MlKem768 => {
                return ml_kem::MlKem768
                    .unsafe_inject_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::UnsafeInjectKey)
            }
            Request::UnsafeInjectKey(req) if req.mechanism == Mechanism::MlKem1024 => {
                return ml_kem::MlKem1024
                    .unsafe_inject_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::UnsafeInjectKey)
            }
            Request::UnsafeInjectKey(req) if req.mechanism == Mechanism::MlKem512 => {
                return ml_kem::MlKem512
                    .unsafe_inject_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::UnsafeInjectKey)
            }
            Request::UnsafeInjectKey(req) if req.mechanism == Mechanism::MlKem768 => {
                return ml_kem::MlKem768
                    .unsafe_inject_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::UnsafeInjectKey)
            }
            Request::UnsafeInjectKey(req) if req.mechanism == Mechanism::MlKem1024 => {
                return ml_kem::MlKem1024
                    .unsafe_inject_key(&mut _keystore(_resources, _core_ctx)?, req)
                    .map(Reply::UnsafeInjectKey)
            }
            _ => {}
        }
        Err(Error::RequestNotAvailable)
    }
}
