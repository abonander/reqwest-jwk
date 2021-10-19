use serde::{Deserializer, Deserialize};
use openssl::bn::BigNum;
use serde::de::Error;
use jwt::PKeyWithDigest;
use openssl::pkey::{Public, PKey};
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::ec::{EcKey, EcGroup};
use openssl::nid::Nid;

/// The JSON Web Key structure itself.
#[derive(serde::Deserialize)]
#[non_exhaustive]
pub struct Key {
    #[serde(rename = "kid")]
    pub key_id: Option<String>,

    #[serde(flatten)]
    pub key_type: KeyType
}

#[derive(serde::Deserialize)]
#[serde(tag = "kty", rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum KeyType {
    Rsa {
        alg: RsaAlg,
        #[serde(deserialize_with = "bignum_from_base64")]
        n: BigNum,
        #[serde(deserialize_with = "bignum_from_base64")]
        e: BigNum,
    },
    Ec {
        alg: EcAlg,
        crv: EcCurve,
        #[serde(deserialize_with = "bignum_from_base64")]
        x: BigNum,
        #[serde(deserialize_with = "bignum_from_base64")]
        y: BigNum
    }
    // omitting HMAC for now
}

#[derive(serde::Deserialize)]
#[non_exhaustive]
pub enum RsaAlg {
    RS256,
    RS384,
    RS512
}

#[derive(serde::Deserialize)]
#[non_exhaustive]
pub enum EcCurve {
    #[serde(rename = "P-256")]
    P256,
}

#[derive(serde::Deserialize)]
#[non_exhaustive]
pub enum EcAlg {
    ES256,
    ES384,
    ES512
}

impl Key {
    /// Convert this `Key` into a type suitable for consumption by the `jwt` crate.
    pub fn into_jwt_key(self) -> Result<PKeyWithDigest<Public>, openssl::error::ErrorStack> {
        Ok(match self.key_type {
            KeyType::Rsa { alg, n, e} => {
                PKeyWithDigest {
                    digest: match alg {
                        RsaAlg::RS256 => MessageDigest::sha256(),
                        RsaAlg::RS384 => MessageDigest::sha384(),
                        RsaAlg::RS512 => MessageDigest::sha512()
                    },
                    key: PKey::from_rsa(Rsa::from_public_components(n, e)?)?
                }
            }
            KeyType::Ec { alg, crv, x, y} => {
                let group = EcGroup::from_curve_name(match crv {
                    EcCurve::P256 => Nid::X9_62_PRIME256V1,
                })?;

                PKeyWithDigest {
                    digest: match alg {
                        EcAlg::ES256 => MessageDigest::sha256(),
                        EcAlg::ES384 => MessageDigest::sha384(),
                        EcAlg::ES512 => MessageDigest::sha512()
                    },
                    key: PKey::from_ec_key(EcKey::from_public_key_affine_coordinates(
                        &group,
                        &x,
                        &y
                    )?)?
                }
            }
        })
    }
}

/// Decode a big-endian encoded [`openssl::bn::BigNum`] from a base64url string.
fn bignum_from_base64<'de, D: Deserializer<'de>>(de: D) -> Result<BigNum, D::Error> {
    let data = base64::decode_config(String::deserialize(de)?, base64::URL_SAFE)
        .map_err(D::Error::custom)?;
    BigNum::from_slice(&data).map_err(D::Error::custom)
}