use trussed::store::Keystore;
use trussed_core::{
    api::{reply, request},
    Error,
};

pub fn encrypt(
    _req: &request::Encrypt,
    _keystore: &mut impl Keystore,
) -> Result<reply::Encrypt, Error> {
    todo!()
}
