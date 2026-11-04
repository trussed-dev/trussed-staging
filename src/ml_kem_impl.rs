use ml_dsa::KeyExport;
use rand_core::{CryptoRng, RngCore};
use trussed::{
    key::{self, Kind, Secrecy},
    serde_extensions::ExtensionImpl,
    service::ServiceResources,
    store::Keystore,
    types::CoreContext,
    Platform,
};
use trussed_core::{
    api::{reply, request},
    types::{KeyId, KeySerialization, Mechanism, SerializedKey, ShortData},
    Error,
};
use trussed_kem::{
    KemDecapsulateReply, KemDecapsulateRequest, KemEncapsulateReply, KemEncapsulateRequest,
    KemExtension, KemReply, KemRequest,
};

use ml_kem::{kem::TryDecapsulate, Kem, MlKem1024, MlKem512, MlKem768, ParameterSet, Seed, B32};

use hybrid_array::Array;

use crate::{StagingBackend, StagingContext};

impl ParamsInternal for MlKem512 {
    const KIND: Kind = Kind::MlKem512;
    const MECHANISM: Mechanism = Mechanism::MlKem512;
    fn seed_to_decapsulation(seed: Seed) -> Self::DecapsulationKey {
        Self::DecapsulationKey::from_seed(seed)
    }
    fn encapsulation_to_bytes(
        value: &Self::EncapsulationKey,
    ) -> ml_kem::Key<Self::EncapsulationKey> {
        value.to_bytes()
    }
    fn bytes_to_encapsulation(
        value: ml_kem::Key<Self::EncapsulationKey>,
    ) -> Result<Self::EncapsulationKey, ml_kem::InvalidKey> {
        Self::EncapsulationKey::new(&value)
    }
    fn decapsulation_to_encapsulation(value: &Self::DecapsulationKey) -> &Self::EncapsulationKey {
        value.encapsulation_key()
    }
    fn encapsulate_with_rng<R: CryptoRng + RngCore>(
        &self,
        encapsulation_key: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> (
        Array<u8, Self::CiphertextSize>,
        Array<u8, Self::SharedKeySize>,
    ) {
        let mut m = B32::default();
        rng.fill_bytes(&mut m.0);
        encapsulation_key.encapsulate_deterministic(&m)
    }
}

impl ParamsInternal for MlKem768 {
    const KIND: Kind = Kind::MlKem768;
    const MECHANISM: Mechanism = Mechanism::MlKem768;
    fn seed_to_decapsulation(seed: Seed) -> Self::DecapsulationKey {
        Self::DecapsulationKey::from_seed(seed)
    }
    fn encapsulation_to_bytes(
        value: &Self::EncapsulationKey,
    ) -> ml_kem::Key<Self::EncapsulationKey> {
        value.to_bytes()
    }
    fn bytes_to_encapsulation(
        value: ml_kem::Key<Self::EncapsulationKey>,
    ) -> Result<Self::EncapsulationKey, ml_kem::InvalidKey> {
        Self::EncapsulationKey::new(&value)
    }
    fn decapsulation_to_encapsulation(value: &Self::DecapsulationKey) -> &Self::EncapsulationKey {
        value.encapsulation_key()
    }
    fn encapsulate_with_rng<R: CryptoRng + RngCore>(
        &self,
        encapsulation_key: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> (
        Array<u8, Self::CiphertextSize>,
        Array<u8, Self::SharedKeySize>,
    ) {
        let mut m = B32::default();
        rng.fill_bytes(&mut m.0);
        encapsulation_key.encapsulate_deterministic(&m)
    }
}

impl ParamsInternal for MlKem1024 {
    const KIND: Kind = Kind::MlKem1024;
    const MECHANISM: Mechanism = Mechanism::MlKem1024;
    fn seed_to_decapsulation(seed: Seed) -> Self::DecapsulationKey {
        Self::DecapsulationKey::from_seed(seed)
    }
    fn encapsulation_to_bytes(
        value: &Self::EncapsulationKey,
    ) -> ml_kem::Key<Self::EncapsulationKey> {
        value.to_bytes()
    }
    fn bytes_to_encapsulation(
        value: ml_kem::Key<Self::EncapsulationKey>,
    ) -> Result<Self::EncapsulationKey, ml_kem::InvalidKey> {
        Self::EncapsulationKey::new(&value)
    }
    fn decapsulation_to_encapsulation(value: &Self::DecapsulationKey) -> &Self::EncapsulationKey {
        value.encapsulation_key()
    }

    fn encapsulate_with_rng<R: CryptoRng + RngCore>(
        &self,
        encapsulation_key: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> (
        Array<u8, Self::CiphertextSize>,
        Array<u8, Self::SharedKeySize>,
    ) {
        let mut m = B32::default();
        rng.fill_bytes(&mut m.0);
        encapsulation_key.encapsulate_deterministic(&m)
    }
}

trait ParamsInternal: Kem + ParameterSet {
    const KIND: Kind;
    const MECHANISM: Mechanism;

    fn seed_to_decapsulation(seed: Seed) -> Self::DecapsulationKey;
    fn decapsulation_to_encapsulation(value: &Self::DecapsulationKey) -> &Self::EncapsulationKey;

    fn encapsulation_to_bytes(
        value: &Self::EncapsulationKey,
    ) -> ml_kem::Key<Self::EncapsulationKey>;
    fn bytes_to_encapsulation(
        value: ml_kem::Key<Self::EncapsulationKey>,
    ) -> Result<Self::EncapsulationKey, ml_kem::InvalidKey>;

    fn load_encapsulation_key(
        &self,
        keystore: &mut impl Keystore,
        key_id: &KeyId,
    ) -> Result<Self::EncapsulationKey, Error> {
        let public_bytes = keystore
            .load_key(Secrecy::Public, Some(Self::KIND), key_id)?
            .material
            .as_slice()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        Self::bytes_to_encapsulation(public_bytes).map_err(|_| Error::InternalError)
    }

    fn load_secret_key(
        &self,
        keystore: &mut impl Keystore,
        key_id: &KeyId,
    ) -> Result<Self::DecapsulationKey, Error> {
        let seed = keystore
            .load_key(Secrecy::Secret, Some(Self::KIND), key_id)?
            .material
            .as_slice()
            .try_into()
            .map_err(|_| Error::InternalError)?;
        Ok(Self::seed_to_decapsulation(seed))
    }

    // Because rand_core is not
    fn encapsulate_with_rng<R: CryptoRng + RngCore>(
        &self,
        encapsulation_key: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> (
        Array<u8, Self::CiphertextSize>,
        Array<u8, Self::SharedKeySize>,
    );
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
            &Self::encapsulation_to_bytes(Self::decapsulation_to_encapsulation(&secret_key)),
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
        let public_key = Self::bytes_to_encapsulation(serialized_key)
            .map_err(|_| Error::InvalidSerializedKey)?;
        let public_id = keystore.store_key(
            req.attributes.persistence,
            Secrecy::Public,
            Self::KIND,
            &Self::encapsulation_to_bytes(&public_key),
        )?;

        Ok(reply::DeserializeKey { key: public_id })
    }

    fn generate_key(
        &self,
        keystore: &mut impl Keystore,
        req: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        // TODO use generate once on rand_core higher
        let mut seed = Default::default();
        // Force type infernce, for some reason ml_dsa::Seed leads does resolve
        if false {
            #[allow(unused)]
            Self::seed_to_decapsulation(seed);
        }
        keystore.rng().fill_bytes(&mut seed.0);
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
        let verifying_key = self.load_encapsulation_key(keystore, &key_id)?;
        if req.format != KeySerialization::Raw {
            return Err(Error::InvalidSerializationFormat);
        }

        let mut serialized_key = SerializedKey::new();
        serialized_key
            .extend_from_slice(&Self::encapsulation_to_bytes(&verifying_key))
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
    fn encapsulate(
        &self,
        keystore: &mut impl Keystore,
        req: &KemEncapsulateRequest,
    ) -> Result<KemEncapsulateReply, Error> {
        assert_eq!(req.mechanism, Self::MECHANISM);
        let encapsulation_key = self.load_encapsulation_key(keystore, &req.key)?;
        let (ciphertext, shared_secret) =
            Self::encapsulate_with_rng(&self, &encapsulation_key, keystore.rng());
        let shared_secret = keystore.store_key(
            req.attributes.persistence,
            Secrecy::Secret,
            Kind::Shared(shared_secret.len()),
            &shared_secret,
        )?;
        let mut ciphertext_data = ShortData::new();
        ciphertext_data.extend_from_slice(&ciphertext).unwrap();

        Ok(KemEncapsulateReply {
            ciphertext: ciphertext_data,
            shared_secret,
        })
    }
    fn decapsulate(
        &self,
        keystore: &mut impl Keystore,
        req: &KemDecapsulateRequest,
    ) -> Result<KemDecapsulateReply, Error> {
        assert_eq!(req.mechanism, Self::MECHANISM);
        let key = self.load_secret_key(keystore, &req.key)?;
        let ct = (&*req.ciphertext)
            .try_into()
            .map_err(|_| Error::WrongMessageLength)?;
        // AEAD Error doesn't make much sense but it's the closest.
        let shared_secret = key.try_decapsulate(&ct).map_err(|_| Error::AeadError)?;
        let key = keystore.store_key(
            req.attributes.persistence,
            Secrecy::Secret,
            Kind::Shared(shared_secret.len()),
            &shared_secret,
        )?;

        Ok(KemDecapsulateReply { key })
    }
}

impl ExtensionImpl<KemExtension> for StagingBackend {
    fn extension_request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut StagingContext,
        request: &KemRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<KemReply, Error> {
        let mut keystore = resources.keystore(core_ctx.path.clone())?;
        match request {
            KemRequest::Encapsulate(req) if req.mechanism == Mechanism::MlKem512 => MlKem512
                .encapsulate(&mut keystore, req)
                .map(KemReply::Encapsulate),
            KemRequest::Encapsulate(req) if req.mechanism == Mechanism::MlKem768 => MlKem768
                .encapsulate(&mut keystore, req)
                .map(KemReply::Encapsulate),
            KemRequest::Encapsulate(req) if req.mechanism == Mechanism::MlKem1024 => MlKem1024
                .encapsulate(&mut keystore, req)
                .map(KemReply::Encapsulate),
            KemRequest::Decapsulate(req) if req.mechanism == Mechanism::MlKem512 => MlKem512
                .decapsulate(&mut keystore, req)
                .map(KemReply::Decapsulate),
            KemRequest::Decapsulate(req) if req.mechanism == Mechanism::MlKem768 => MlKem768
                .decapsulate(&mut keystore, req)
                .map(KemReply::Decapsulate),
            KemRequest::Decapsulate(req) if req.mechanism == Mechanism::MlKem1024 => MlKem1024
                .decapsulate(&mut keystore, req)
                .map(KemReply::Decapsulate),
            _ => Err(Error::RequestNotAvailable),
        }
    }
}
