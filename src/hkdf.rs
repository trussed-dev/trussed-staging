// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use hkdf::Hkdf;
use sha2::Sha256;
use trussed::{
    config::MAX_MEDIUM_DATA_LENGTH,
    key::{Kind, Secrecy},
    serde_extensions::ExtensionImpl,
    service::{ClientKeystore, Keystore, ServiceResources},
    store::Store,
    types::{Bytes, CoreContext, MediumData, ShortData},
    Error, Platform,
};
use trussed_hkdf::{
    HkdfExpandReply, HkdfExpandRequest, HkdfExtension, HkdfExtractReply, HkdfExtractRequest,
    HkdfReply, HkdfRequest, KeyOrData, OkmId,
};

use crate::{StagingBackend, StagingContext};

impl ExtensionImpl<HkdfExtension> for StagingBackend {
    fn extension_request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut StagingContext,
        request: &HkdfRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<HkdfReply, Error> {
        let mut keystore = resources.keystore(core_ctx.path.clone())?;
        Ok(match request {
            HkdfRequest::Extract(req) => extract(req, &mut keystore)?.into(),
            HkdfRequest::Expand(req) => expand(req, &mut keystore)?.into(),
        })
    }
}

fn get_mat<S: Store>(
    req: &KeyOrData<MAX_MEDIUM_DATA_LENGTH>,
    keystore: &mut ClientKeystore<S>,
) -> Result<MediumData, Error> {
    Ok(match req {
        KeyOrData::Data(d) => d.clone(),
        KeyOrData::Key(key_id) => {
            let key_mat = keystore.load_key(Secrecy::Secret, None, key_id)?;
            if !matches!(key_mat.kind, Kind::Symmetric(..) | Kind::Shared(..)) {
                warn!("Attempt to HKDF on a private key");
                return Err(Error::MechanismInvalid);
            }
            Bytes::from_slice(&key_mat.material).map_err(|_| {
                warn!("Attempt to HKDF a too large key");
                Error::InternalError
            })?
        }
    })
}

fn extract<S: Store>(
    req: &HkdfExtractRequest,
    keystore: &mut ClientKeystore<S>,
) -> Result<HkdfExtractReply, Error> {
    let ikm = get_mat(&req.ikm, keystore)?;
    let salt = req
        .salt
        .as_ref()
        .map(|s| get_mat(s, keystore))
        .transpose()?;
    let salt_ref = salt.as_deref().map(|d| &**d);
    let (prk, _) = Hkdf::<Sha256>::extract(salt_ref, &ikm);
    assert_eq!(prk.len(), 256 / 8);
    let key_id = keystore.store_key(
        req.storage,
        Secrecy::Secret,
        Kind::Symmetric(prk.len()),
        &prk,
    )?;
    Ok(HkdfExtractReply { okm: OkmId(key_id) })
}
fn expand<S: Store>(
    req: &HkdfExpandRequest,
    keystore: &mut ClientKeystore<S>,
) -> Result<HkdfExpandReply, Error> {
    let prk = keystore.load_key(Secrecy::Secret, None, &req.prk.0)?;
    if !matches!(prk.kind, Kind::Symmetric(32)) {
        error!("Attempt to use wrong key for HKDF expand");
        return Err(Error::ObjectHandleInvalid);
    }

    let hkdf = Hkdf::<Sha256>::from_prk(&prk.material).map_err(|_| {
        warn!("Failed to create HKDF");
        Error::InternalError
    })?;
    let mut okm = ShortData::new();
    okm.resize_default(req.len).map_err(|_| {
        error!("Attempt to run HKDF with too large output");
        Error::WrongMessageLength
    })?;
    hkdf.expand(&req.info, &mut okm).map_err(|_| {
        warn!("Bad HKDF expand length");
        Error::WrongMessageLength
    })?;

    let key = keystore.store_key(
        req.storage,
        Secrecy::Secret,
        Kind::Symmetric(okm.len()),
        &okm,
    )?;

    Ok(HkdfExpandReply { key })
}
