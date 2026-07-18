use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use ts_rs::TS;

use crate::{MAX_ARBITRARY_BYTES, MAX_CIPHERTEXT_BYTES, ValidationError};

fn decode_base64(value: &str, limit: usize) -> Result<Vec<u8>, ValidationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ValidationError::Invalid("base64url"))?;
    if bytes.len() > limit {
        return Err(ValidationError::TooLarge {
            field: "bytes",
            limit,
        });
    }
    Ok(bytes)
}

macro_rules! fixed_bytes {
    ($name:ident, $size:expr, hex, $ts:literal) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, TS)]
        #[ts(type = $ts)]
        pub struct $name(pub [u8; $size]);
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(
                    &self
                        .0
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                )
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                if value.len() != $size * 2
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(D::Error::custom("invalid lowercase hex"));
                }
                let mut bytes = [0; $size];
                for (index, output) in bytes.iter_mut().enumerate() {
                    *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                        .map_err(D::Error::custom)?;
                }
                Ok(Self(bytes))
            }
        }
    };
    ($name:ident, $size:expr, base64, $ts:literal) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, TS)]
        #[ts(type = $ts)]
        pub struct $name(pub [u8; $size]);
        impl $name {
            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let bytes = decode_base64(&String::deserialize(deserializer)?, $size)
                    .map_err(D::Error::custom)?;
                Ok(Self(
                    bytes
                        .try_into()
                        .map_err(|_| D::Error::custom("invalid byte length"))?,
                ))
            }
        }
    };
}

fixed_bytes!(Sha256Digest, 32, hex, "Sha256Hex");
fixed_bytes!(XChaChaNonce, 24, base64, "Base64Url");
fixed_bytes!(Ed25519SignatureBytes, 64, base64, "Base64Url");
fixed_bytes!(
    PairingRequestNonce,
    32,
    base64,
    "PairingRequestNonceBase64Url"
);
fixed_bytes!(
    Ed25519PublicKeyBytes,
    32,
    base64,
    "Ed25519PublicKeyBase64Url"
);
fixed_bytes!(X25519PublicKeyBytes, 32, base64, "X25519PublicKeyBase64Url");
fixed_bytes!(
    InstallationTokenProof,
    32,
    base64,
    "InstallationTokenProofBase64Url"
);

macro_rules! bounded_bytes {
    ($name:ident, $limit:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
        #[serde(try_from = "String", into = "String")]
        #[ts(type = "Base64Url")]
        pub struct $name(Vec<u8>);
        impl $name {
            pub fn new(bytes: Vec<u8>) -> Result<Self, ValidationError> {
                if bytes.len() > $limit {
                    return Err(ValidationError::TooLarge {
                        field: "bytes",
                        limit: $limit,
                    });
                }
                Ok(Self(bytes))
            }
            pub fn as_slice(&self) -> &[u8] {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = ValidationError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(decode_base64(&value, $limit)?)
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                URL_SAFE_NO_PAD.encode(value.0)
            }
        }
    };
}
bounded_bytes!(BoundedCiphertext, MAX_CIPHERTEXT_BYTES);
bounded_bytes!(BoundedBytes, MAX_ARBITRARY_BYTES);
