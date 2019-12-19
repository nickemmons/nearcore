use serde::de::{Error as _, Unexpected};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::{identity, TryFrom};
use std::fmt::{self, Debug, Display, Formatter};

macro_rules! to_str {
    ($v:expr) => {
        identity::<String>($v.into()).as_str()
    };
}

macro_rules! common_conversions {
    ($ty:ty, $l:lit, $bytes:expr, $what:lit) => {
        impl TryFrom<&[u8]> for $ty {
            type Error = ();

            fn try_from(value: &[u8]) -> Result<Self, ()> {
                if value.len() == $l {
                    Self::try_from(array_ref!(value, 0, $l)).or(Err(()))
                } else {
                    Err(())
                }
            }
        }

        impl TryFrom<&str> for $ty {
            type Error = ();

            fn try_from(value: &str) -> Result<Self, ()> {
                let mut buf = [0; $l];
                if bs58::decode(value).into(&mut buf[..]) == Ok($l) {
                    Self::try_from(&buf).or(Err(()))
                } else {
                    Err(())
                }
            }
        }

        impl TryFrom<String> for $ty {
            type Error = ();

            fn try_from(value: String) -> Result<Self, ()> {
                Self::try_from(value.as_str())
            }
        }

        impl AsRef<[u8; $l]> for $ty {
            fn as_ref(&self) -> &[u8; $l] {
                $bytes
            }
        }

        impl AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                <Self as AsRef<[u8; $l]>>::as_ref(self)
            }
        }

        impl Into<[u8; $l]> for $ty {
            fn into(self) -> [u8; $l] {
                *self.as_ref()
            }
        }

        impl Into<[u8; $l]> for &$ty {
            fn into(self) -> [u8; $l] {
                *self.as_ref()
            }
        }

        impl Into<String> for $ty {
            fn into(self) -> String {
                bs58::encode(self).into_string()
            }
        }

        impl Into<String> for &$ty {
            fn into(self) -> String {
                bs58::encode(self).into_string()
            }
        }

        impl Debug for $ty {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                f.write_str(to_str!(self))
            }
        }

        impl Display for $ty {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                f.write_str(to_str!(self))
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = <&str as Deserialize<'de>>::deserialize(deserializer)?;
                Self::try_from(s).map_err(|_| {
                    D::Error::invalid_value(Unexpected::Str(s), &concat!("a valid ", $what))
                })
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(to_str!(self))
            }
        }
    };
}

macro_rules! value_type {
    ($vis:vis, $ty:ident, $l:lit, $what:ident) => {
        #[derive(Copy, Clone)]
        $vis struct $ty(pub [u8; $l]);

        impl PartialEq for $ty {
            fn eq(&self, other: &Self) -> bool {
                self.0[..] == other.0[..]
            }
        }

        impl Eq for $ty {}

        impl AsMut<[u8; $l]> for $ty {
            fn as_mut(&mut self) -> &mut [u8; $l] {
                &mut self.0
            }
        }

        impl AsMut<[u8]> for $ty {
            fn as_mut(&mut self) -> &mut [u8] {
                &mut self.0[..]
            }
        }

        impl From<&[u8; $l]> for $ty {
            fn from(value: &[u8; $l]) -> Self {
                Self(*value)
            }
        }

        common_conversions!($ty, $l, &self.0, $what);
    };
}
