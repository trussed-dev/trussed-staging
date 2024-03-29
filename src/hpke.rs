use crate::StagingBackend;

use serde_byte_array::ByteArray;
use trussed::{key, serde_extensions::ExtensionImpl, store::keystore::Keystore, Bytes};
use trussed_hpke::*;

type HkdfSha256 = hkdf::Hkdf<sha2::Sha256>;
type HkdfSha256Extract = hkdf::HkdfExtract<sha2::Sha256>;

pub const NSK: usize = 32;
pub const NPK: usize = 32;
pub const N_ENC: usize = 32;
pub const N_SECRET: usize = 32;

pub const NDH: usize = 64;
pub const KEM_ID: u16 = 0x20;
pub const KDF_ID: u16 = 0x01;
pub const AEAD_ID: u16 = 0x03;

use rand_core::{CryptoRng, RngCore};
use salty::agreement as x25519;

const KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";

fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> (HkdfSha256, [u8; 32]) {
    let mut extract_ctx = HkdfSha256Extract::new(Some(salt));
    extract_ctx.input_ikm(b"HPKE-v1");
    extract_ctx.input_ikm(suite_id);
    extract_ctx.input_ikm(label);
    extract_ctx.input_ikm(ikm);
    let (prk, hkdf) = extract_ctx.finalize();
    (hkdf, prk.into())
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &HkdfSha256,
    label: &[u8],
    info: &[u8],
    buffer: &mut [u8],
) -> Result<(), hkdf::InvalidLength> {
    let Ok(l): Result<u16, _> = buffer.len().try_into() else {
        return Err(hkdf::InvalidLength);
    };
    prk.expand_multi_info(
        &[&l.to_be_bytes(), b"HPKE-v1", suite_id, label, info],
        buffer,
    )
}

fn extract_and_expand(dh: x25519::SharedSecret, kem_context: &[u8]) -> [u8; N_SECRET] {
    let (prk, _) = labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", &dh.to_bytes());
    let mut shr = [0; N_SECRET];
    labeled_expand(KEM_SUITE_ID, &prk, b"shared_secret", kem_context, &mut shr)
        .expect("Length of shr is known to be OK");
    shr
}

fn encap<R: CryptoRng + RngCore>(
    pkr: x25519::PublicKey,
    cspnrg: &mut R,
) -> ([u8; N_SECRET], x25519::PublicKey) {
    let seed = &mut [0; 32];
    cspnrg.fill_bytes(seed);
    let secret = x25519::SecretKey::from_seed(seed);
    let dh = secret.agree(&pkr);
    let enc = secret.public();

    let kem_context = &mut [0; 64];
    kem_context[0..32].copy_from_slice(&enc.to_bytes());
    kem_context[32..].copy_from_slice(&pkr.to_bytes());
    let shared_secret = extract_and_expand(dh, kem_context);
    return (shared_secret, enc);
}

fn decap(enc: x25519::PublicKey, skr: x25519::SecretKey) -> [u8; N_SECRET] {
    let dh = skr.agree(&enc);
    let kem_context = &mut [0; 64];
    kem_context[0..32].copy_from_slice(&enc.to_bytes());
    kem_context[32..].copy_from_slice(&skr.public().to_bytes());
    extract_and_expand(dh, kem_context)
}

enum Role {
    Sender,
    Receiver,
}

const MODE_BASE: u8 = 0x00;

#[cfg_attr(test, derive(Clone))]
struct Context {
    key: [u8; NK],
    base_nonce: [u8; NN],
    exporter_secret: [u8; NH],
    // Our limited version only allows one encryption/decryption
    // seq: u128,
}

const NK: usize = 32;
const NN: usize = 12;
const NH: usize = 32;

fn key_schedule(role: Role, shared_secret: [u8; N_SECRET], info: &[u8]) -> Context {
    let (_, psk_id_hash) = labeled_extract(HPKE_SUITE_ID, b"", b"psk_id_hash", b"");
    let (_, info_hash) = labeled_extract(HPKE_SUITE_ID, b"", b"info_hash", info);
    let mut key_schedule_context = [0; 65];
    key_schedule_context[0] = MODE_BASE;
    key_schedule_context[1..33].copy_from_slice(&psk_id_hash);
    key_schedule_context[33..].copy_from_slice(&info_hash);
    let (secret, _) = labeled_extract(HPKE_SUITE_ID, &shared_secret, b"secret", b"");
    let mut key = [0; NK];
    labeled_expand(
        HPKE_SUITE_ID,
        &secret,
        b"key",
        &key_schedule_context,
        &mut key,
    )
    .expect("KEY is not too large");
    let mut base_nonce = [0; NN];
    labeled_expand(
        HPKE_SUITE_ID,
        &secret,
        b"base_nonce",
        &key_schedule_context,
        &mut base_nonce,
    )
    .expect("NONCE is not too large");
    let mut exporter_secret = [0; NH];
    labeled_expand(
        HPKE_SUITE_ID,
        &secret,
        b"exp",
        &key_schedule_context,
        &mut exporter_secret,
    )
    .expect("EXP is not too large");
    Context {
        key,
        base_nonce,
        exporter_secret,
    }
}

fn setup_base_s<R: CryptoRng + RngCore>(
    pkr: x25519::PublicKey,
    info: &[u8],
    cspnrg: &mut R,
) -> (x25519::PublicKey, Context) {
    let (shared_secret, enc) = encap(pkr, cspnrg);
    (enc, key_schedule(Role::Sender, shared_secret, info))
}

fn setup_base_r(
    enc: x25519::PublicKey,
    skr: x25519::SecretKey,
    info: &[u8],
) -> (x25519::PublicKey, Context) {
    let shared_secret = decap(enc, skr);
    (enc, key_schedule(Role::Receiver, shared_secret, info))
}

const TAG_LEN: usize = 16;

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};

impl Context {
    fn seal_in_place_detached(self, aad: &[u8], plaintext: &mut [u8]) -> [u8; TAG_LEN] {
        // We don't increment because the simplified API only allows 1 encryption
        let nonce = (&self.base_nonce).into();
        let aead = ChaCha20Poly1305::new((&self.key).into());
        let tag = aead
            .encrypt_in_place_detached(nonce, aad, plaintext)
            .expect("Not used to encrypt data too large");

        tag.into()
    }

    fn open_in_place_detached(
        self,
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: [u8; TAG_LEN],
    ) -> Result<(), aead::Error> {
        let nonce = (&self.base_nonce).into();
        let aead = ChaCha20Poly1305::new((&self.key).into());
        aead.decrypt_in_place_detached(nonce, aad, ciphertext, (&tag).into())
    }
}

fn seal<R: CryptoRng + RngCore>(
    pkr: x25519::PublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &mut [u8],
    csprng: &mut R,
) -> (x25519::PublicKey, [u8; TAG_LEN]) {
    let (enc, ctx) = setup_base_s(pkr, info, csprng);
    let tag = ctx.seal_in_place_detached(aad, plaintext);
    return (enc, tag);
}

fn open(
    enc: x25519::PublicKey,
    skr: x25519::SecretKey,
    info: &[u8],
    aad: &[u8],
    ciphertext: &mut [u8],
    tag: [u8; TAG_LEN],
) -> Result<(), aead::Error> {
    let (_, ctx) = setup_base_r(enc, skr, info);
    ctx.open_in_place_detached(aad, ciphertext, tag)
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;

    use hex_literal::hex;

    use super::*;

    struct TestRng<'a>(&'a [u8]);
    impl<'a> CryptoRng for TestRng<'a> {}
    impl<'a> RngCore for TestRng<'a> {
        fn next_u32(&mut self) -> u32 {
            let (value, rem) = self.0.split_first_chunk().unwrap();
            self.0 = rem;
            u32::from_be_bytes(*value)
        }
        fn next_u64(&mut self) -> u64 {
            let (value, rem) = self.0.split_first_chunk().unwrap();
            self.0 = rem;
            u64::from_be_bytes(*value)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let (value, rem) = self.0.split_at(dest.len());
            self.0 = rem;
            dest.copy_from_slice(value);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            if self.0.len() < dest.len() {
                let error_code: NonZeroU32 = rand_core::Error::CUSTOM_START.try_into().unwrap();
                return Err(rand_core::Error::from(error_code));
            }
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[allow(non_snake_case)]
    #[test]
    fn chacha20() {
        let info = hex!("4f6465206f6e2061204772656369616e2055726e");
        let pkEm = hex!("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let skEm = hex!("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
        let alice_sk = x25519::SecretKey::from_seed(&skEm);
        assert_eq!(pkEm, alice_sk.public().to_bytes());
        let pkRm = hex!("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let skRm = hex!("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let bob_sk = x25519::SecretKey::from_seed(&skRm);
        assert_eq!(pkRm, bob_sk.public().to_bytes());
        let expected_shared_secret =
            hex!("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");
        let (shared_secret, enc) = encap(bob_sk.public(), &mut TestRng(&skEm));
        assert_eq!(enc.to_bytes(), pkEm);
        assert_eq!(shared_secret, expected_shared_secret);

        assert_eq!(
            decap(alice_sk.public(), bob_sk.clone()),
            expected_shared_secret
        );
        let (enc, ctx) = setup_base_s(bob_sk.public(), &info, &mut TestRng(&skEm));
        assert_eq!(enc.to_bytes(), pkEm);
        assert_eq!(
            ctx.key,
            hex!("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91")
        );
        assert_eq!(ctx.base_nonce, hex!("5c4d98150661b848853b547f"));
        assert_eq!(
            ctx.exporter_secret,
            hex!("a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922")
        );

        let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
        let mut buffer = pt;
        let aad = hex!("436f756e742d30");
        let ct = hex!("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b");
        let expected_tag = hex!("60b4db21993c62ce81883d2dd1b51a28");

        let (enc, tag) = seal(
            bob_sk.public(),
            &info,
            &aad,
            &mut buffer,
            &mut TestRng(&skEm),
        );
        assert_eq!(enc.to_bytes(), pkEm);
        assert_eq!(buffer, ct);
        assert_eq!(tag, expected_tag);
        open(enc, bob_sk, &info, &aad, &mut buffer, tag).unwrap();
        assert_eq!(buffer, pt);
    }
}

impl StagingBackend {}

// fn load_public_key(
//     keystore: &mut impl Keystore,
//     key_id: &KeyId,
// ) -> Result<x25519::PublicKey, Error> {
//     let public_bytes: [u8; 32] = keystore
//         .load_key(key::Secrecy::Public, Some(key::Kind::X255), key_id)?
//         .material
//         .as_slice()
//         .try_into()
//         .map_err(|_| Error::InternalError)?;

//     let public_key = public_bytes.into();

//     Ok(public_key)
// }

// fn load_secret_key(
//     keystore: &mut impl Keystore,
//     key_id: &KeyId,
// ) -> Result<agreement::SecretKey, Error> {
//     let seed: [u8; 32] = keystore
//         .load_key(key::Secrecy::Secret, Some(key::Kind::X255), key_id)?
//         .material
//         .as_slice()
//         .try_into()
//         .map_err(|_| Error::InternalError)?;

//     let keypair = agreement::SecretKey::from_seed(&seed);
//     Ok(keypair)
// }

impl ExtensionImpl<HpkeExtension> for StagingBackend {
    fn extension_request<P: trussed::Platform>(
        &mut self,
        core_ctx: &mut trussed::types::CoreContext,
        backend_ctx: &mut Self::Context,
        request: &<HpkeExtension as trussed::serde_extensions::Extension>::Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<<HpkeExtension as trussed::serde_extensions::Extension>::Reply, trussed::Error>
    {
        let keystore = &mut resources.keystore(core_ctx.path.clone())?;

        match request {
            HpkeRequest::Seal(req) => {
                let public_bytes: [u8; 32] = keystore
                    .load_key(key::Secrecy::Public, Some(key::Kind::X255), &req.key)?
                    .material
                    .as_slice()
                    .try_into()
                    .map_err(|_| trussed::Error::InternalError)?;
                let public_key = x25519::PublicKey::from(public_bytes);
                let mut pt = req.plaintext.clone();
                let (pk, tag) = seal(public_key, &req.info, &req.aad, &mut pt, keystore.rng());
                let enc = keystore.store_key(
                    req.enc_location,
                    key::Secrecy::Public,
                    key::Kind::X255,
                    &pk.to_bytes(),
                )?;
                Ok(HpkeSealReply {
                    enc,
                    ciphertext: pt,
                    tag: tag.into(),
                }
                .into())
            }
            HpkeRequest::Open(req) => {
                let public_bytes: [u8; 32] = keystore
                    .load_key(key::Secrecy::Public, Some(key::Kind::X255), &req.enc_key)?
                    .material
                    .as_slice()
                    .try_into()
                    .map_err(|_| trussed::Error::InternalError)?;
                let enc = x25519::PublicKey::from(public_bytes);
                let secret_bytes: [u8; 32] = keystore
                    .load_key(key::Secrecy::Secret, Some(key::Kind::X255), &req.enc_key)?
                    .material
                    .as_slice()
                    .try_into()
                    .map_err(|_| trussed::Error::InternalError)?;
                let secret_key = x25519::SecretKey::from_seed(&secret_bytes);

                let mut ct = req.ciphertext.clone();
                open(
                    enc,
                    secret_key,
                    &req.info,
                    &req.aad,
                    &mut ct,
                    req.tag.into(),
                )
                .map_err(|_| trussed::Error::AeadError)?;

                Ok(HpkeOpenReply { plaintext: ct }.into())
            }
        }
    }
}
