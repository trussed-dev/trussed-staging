// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use generic_array::GenericArray;
use trussed::{
    config::MAX_SERIALIZED_KEY_LENGTH,
    error::Error,
    key::{self, Kind, Secrecy},
    platform::Platform,
    serde_extensions::ExtensionImpl,
    service::ServiceResources,
    store::{filestore::Filestore, keystore::Keystore},
    types::{Bytes, CoreContext},
};
use trussed_wrap_key_to_file::{
    reply, request, WrapKeyToFileExtension, WrapKeyToFileReply, WrapKeyToFileRequest,
};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const KIND: Kind = Kind::Symmetric(KEY_LEN);
const WRAPPED_TO_FILE_LEN: usize = MAX_SERIALIZED_KEY_LENGTH + NONCE_LEN + TAG_LEN;

fn wrap_key_to_file(
    keystore: &mut impl Keystore,
    filestore: &mut impl Filestore,
    request: &request::WrapKeyToFile,
) -> Result<reply::WrapKeyToFile, Error> {
    if !matches!(
        request.mechanism,
        trussed::types::Mechanism::Chacha8Poly1305
    ) {
        return Err(Error::MechanismInvalid);
    }

    use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
    use chacha20poly1305::ChaCha8Poly1305;
    use rand_core::RngCore as _;

    let serialized_key = keystore.load_key(Secrecy::Secret, None, &request.key)?;

    let mut data = Bytes::<WRAPPED_TO_FILE_LEN>::from_slice(&serialized_key.serialize()).unwrap();
    let material_len = data.len();
    data.resize_default(material_len + NONCE_LEN).unwrap();
    let (material, nonce) = data.split_at_mut(material_len);
    keystore.rng().fill_bytes(nonce);
    let nonce = (&*nonce).try_into().unwrap();

    let key = keystore.load_key(Secrecy::Secret, Some(KIND), &request.wrapping_key)?;
    let chachakey: [u8; KEY_LEN] = (&*key.material).try_into().unwrap();
    let mut aead = ChaCha8Poly1305::new(&GenericArray::clone_from_slice(&chachakey));
    let tag = aead
        .encrypt_in_place_detached(
            <&GenericArray<_, _> as From<&[u8; NONCE_LEN]>>::from(nonce),
            &request.associated_data,
            material,
        )
        .unwrap();
    data.extend_from_slice(&tag).unwrap();
    filestore.write(&request.path, request.location, &data)?;
    Ok(reply::WrapKeyToFile {})
}

fn unwrap_key_from_file(
    keystore: &mut impl Keystore,
    filestore: &mut impl Filestore,
    request: &request::UnwrapKeyFromFile,
) -> Result<reply::UnwrapKeyFromFile, Error> {
    if !matches!(
        request.mechanism,
        trussed::types::Mechanism::Chacha8Poly1305
    ) {
        return Err(Error::MechanismInvalid);
    }

    use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
    use chacha20poly1305::ChaCha8Poly1305;
    let mut data: Bytes<WRAPPED_TO_FILE_LEN> =
        filestore.read(&request.path, request.file_location)?;

    let data_len = data.len();
    if data_len < TAG_LEN + NONCE_LEN {
        error!("Attempt to unwrap file that doesn't contain a key");
        return Err(Error::InvalidSerializedKey);
    }
    let (tmp, tag) = data.split_at_mut(data_len - TAG_LEN);
    let tmp_len = tmp.len();
    let (material, nonce) = tmp.split_at_mut(tmp_len - NONCE_LEN);

    // Coerce to array
    let nonce = (&*nonce).try_into().unwrap();
    let tag = (&*tag).try_into().unwrap();

    let key = keystore.load_key(key::Secrecy::Secret, Some(KIND), &request.key)?;
    let chachakey: [u8; KEY_LEN] = (&*key.material).try_into().unwrap();
    let mut aead = ChaCha8Poly1305::new(&GenericArray::clone_from_slice(&chachakey));
    if aead
        .decrypt_in_place_detached(
            <&GenericArray<_, _> as From<&[u8; NONCE_LEN]>>::from(nonce),
            &request.associated_data,
            material,
            <&GenericArray<_, _> as From<&[u8; TAG_LEN]>>::from(tag),
        )
        .is_err()
    {
        return Ok(reply::UnwrapKeyFromFile { key: None });
    }
    let key = key::Key::try_deserialize(material)?;
    let info = key::Info {
        flags: key.flags,
        kind: key.kind,
    };
    let key = keystore.store_key(request.key_location, Secrecy::Secret, info, &key.material)?;
    Ok(reply::UnwrapKeyFromFile { key: Some(key) })
}

impl ExtensionImpl<WrapKeyToFileExtension> for super::StagingBackend {
    fn extension_request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &WrapKeyToFileRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<WrapKeyToFileReply, Error> {
        let keystore = &mut resources.keystore(core_ctx.path.clone())?;
        let filestore = &mut resources.filestore(core_ctx.path.clone());
        match request {
            WrapKeyToFileRequest::WrapKeyToFile(request) => {
                wrap_key_to_file(keystore, filestore, request).map(Into::into)
            }
            WrapKeyToFileRequest::UnwrapKeyFromFile(request) => {
                unwrap_key_from_file(keystore, filestore, request).map(Into::into)
            }
        }
    }
}
