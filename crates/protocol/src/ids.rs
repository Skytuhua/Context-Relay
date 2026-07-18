use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{fmt, str::FromStr};
use ts_rs::TS;
use uuid::{Uuid, Variant, Version};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("identifier must be a lowercase hyphenated UUIDv7")]
pub struct InvalidId;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, TS)]
        #[ts(type = "UuidV7")]
        pub struct $name(Uuid);

        impl $name {
            pub fn new(value: Uuid) -> Result<Self, InvalidId> {
                (value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122)
                    .then_some(Self(value))
                    .ok_or(InvalidId)
            }
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }
        impl FromStr for $name {
            type Err = InvalidId;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let uuid = Uuid::parse_str(value).map_err(|_| InvalidId)?;
                if value != uuid.hyphenated().to_string() {
                    return Err(InvalidId);
                }
                Self::new(uuid)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.hyphenated().fmt(f)
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::from_str(&String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

id_type!(AccountId);
id_type!(WorkspaceId);
id_type!(ProjectId);
id_type!(MemoryId);
id_type!(CandidateId);
id_type!(TaskId);
id_type!(SecretRefId);
id_type!(OperationId);
id_type!(RecordId);
id_type!(DeviceId);
id_type!(PlanId);
id_type!(PackageId);
id_type!(ExportId);

pub(crate) fn uuid_v7_from_bytes<T>(
    bytes: &[u8],
    wrap: impl FnOnce(Uuid) -> Result<T, InvalidId>,
) -> Result<T, InvalidId> {
    if bytes.len() != 16 {
        return Err(InvalidId);
    }
    wrap(Uuid::from_slice(bytes).map_err(|_| InvalidId)?)
}
