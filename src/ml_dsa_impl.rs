// Copyright (C) Nitrokey GmbH
// SPDX-License-Identifier: Apache-2.0 or MIT

use rand_core::RngCore;
use trussed::{
    key::{self, Kind, Secrecy},
    store::Keystore,
};
use trussed_core::{
    api::{reply, request},
    types::{KeyId, KeySerialization, Mechanism, SerializedKey, Signature, SignatureSerialization},
    Error,
};

use ml_dsa::{
    Keypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signer, SigningKey, Verifier, VerifyingKey,
};

impl ParamsInternal for MlDsa44 {
    const KIND: Kind = Kind::MlDsa44;
    const MECHANISM: Mechanism = Mechanism::MlDsa44;
}

impl ParamsInternal for MlDsa65 {
    const KIND: Kind = Kind::MlDsa65;
    const MECHANISM: Mechanism = Mechanism::MlDsa65;
}

impl ParamsInternal for MlDsa87 {
    const KIND: Kind = Kind::MlDsa87;
    const MECHANISM: Mechanism = Mechanism::MlDsa87;
}

trait ParamsInternal: MlDsaParams {
    const KIND: Kind;
    const MECHANISM: Mechanism;

    fn load_verifying_key(
        &self,
        keystore: &mut impl Keystore,
        key_id: &KeyId,
    ) -> Result<VerifyingKey<Self>, Error> {
        let public_bytes = keystore
            .load_key(Secrecy::Public, Some(Self::KIND), key_id)?
            .material
            .as_slice()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        Ok(VerifyingKey::decode(&public_bytes))
    }

    fn load_secret_key(
        &self,
        keystore: &mut impl Keystore,
        key_id: &KeyId,
    ) -> Result<SigningKey<Self>, Error> {
        let seed = keystore
            .load_key(Secrecy::Secret, Some(Self::KIND), key_id)?
            .material
            .as_slice()
            .try_into()
            .map_err(|_| Error::InternalError)?;
        Ok(SigningKey::from_seed(&seed))
    }
}

const SEED_LEN: usize = 32;

impl<T: ParamsInternal> Params for T {}

#[allow(private_bounds)]
pub trait Params: ParamsInternal {
    fn derive_key(
        &self,
        keystore: &mut impl Keystore,
        req: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        let base_id = req.base_key;
        let secret_key = self.load_secret_key(keystore, &base_id)?;
        let public_id = keystore.store_key(
            req.attributes.persistence,
            Secrecy::Public,
            Self::KIND,
            &secret_key.verifying_key().encode(),
        )?;

        Ok(reply::DeriveKey { key: public_id })
    }

    fn deserialize_key(
        &self,
        keystore: &mut impl Keystore,
        req: &request::DeserializeKey,
    ) -> Result<reply::DeserializeKey, Error> {
        if req.format != KeySerialization::Raw {
            return Err(Error::InternalError);
        }

        let serialized_key = (&*req.serialized_key)
            .try_into()
            .map_err(|_| Error::InvalidSerializedKey)?;
        let public_key = VerifyingKey::<Self>::decode(&serialized_key);
        let public_id = keystore.store_key(
            req.attributes.persistence,
            Secrecy::Public,
            Self::KIND,
            &public_key.encode(),
        )?;

        Ok(reply::DeserializeKey { key: public_id })
    }

    fn generate_key(
        &self,
        keystore: &mut impl Keystore,
        req: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        let mut seed = Default::default();
        // Force type infernce, for some reason ml_dsa::Seed leads does resolve
        if false {
            #[allow(unused)]
            SigningKey::<Self>::from_seed(&seed);
        }
        keystore.rng().fill_bytes(&mut seed);
        let key_id = keystore.store_key(
            req.attributes.persistence,
            Secrecy::Secret,
            key::Info::from(Self::KIND).with_local_flag(),
            &seed,
        )?;
        Ok(reply::GenerateKey { key: key_id })
    }

    fn serialize_key(
        &self,
        keystore: &mut impl Keystore,
        req: &request::SerializeKey,
    ) -> Result<reply::SerializeKey, Error> {
        let key_id = req.key;
        let verifying_key = self.load_verifying_key(keystore, &key_id)?;
        if req.format != KeySerialization::Raw {
            return Err(Error::InvalidSerializationFormat);
        }

        let mut serialized_key = SerializedKey::new();
        serialized_key
            .extend_from_slice(verifying_key.encode().as_slice())
            .map_err(|_| Error::InternalError)?;
        Ok(reply::SerializeKey { serialized_key })
    }

    fn exists(
        &self,
        keystore: &mut impl Keystore,
        req: &request::Exists,
    ) -> Result<reply::Exists, Error> {
        Ok(reply::Exists {
            exists: keystore.exists_key(Secrecy::Secret, Some(Self::KIND), &req.key),
        })
    }

    fn sign(
        &self,
        keystore: &mut impl Keystore,
        req: &request::Sign,
    ) -> Result<reply::Sign, Error> {
        assert_eq!(Self::MECHANISM, req.mechanism);
        if req.format != SignatureSerialization::Raw {
            return Err(Error::InvalidSerializationFormat);
        }
        let key = self.load_secret_key(keystore, &req.key)?;
        let native_signature = key.sign(&req.message);
        let mut signature = Signature::new();
        signature
            .extend_from_slice(&native_signature.encode())
            .unwrap();
        Ok(reply::Sign { signature })
    }

    fn verify(
        &self,
        keystore: &mut impl Keystore,
        req: &request::Verify,
    ) -> Result<reply::Verify, Error> {
        if req.format != SignatureSerialization::Raw {
            return Err(Error::InvalidSerializationFormat);
        }
        let key = self.load_verifying_key(keystore, &req.key)?;
        let signature_parsed = ml_dsa::Signature::<Self>::decode(
            (*req.signature)
                .try_into()
                .map_err(|_| Error::WrongSignatureLength)?,
        )
        .ok_or(Error::WrongSignatureLength)?;

        let valid = key.verify(&req.message, &signature_parsed).is_ok();
        Ok(reply::Verify { valid })
    }

    fn unsafe_inject_key(
        &self,
        keystore: &mut impl Keystore,
        req: &request::UnsafeInjectKey,
    ) -> Result<reply::UnsafeInjectKey, Error> {
        if req.format != KeySerialization::Raw {
            return Err(Error::InvalidSerializationFormat);
        }
        if req.raw_key.len() != SEED_LEN {
            return Err(Error::InvalidSerializedKey);
        }

        let info = key::Info {
            flags: key::Flags::SENSITIVE,
            kind: Self::KIND,
        };
        let key_id = keystore.store_key(
            req.attributes.persistence,
            Secrecy::Secret,
            info,
            &req.raw_key,
        )?;

        Ok(reply::UnsafeInjectKey { key: key_id })
    }
}
