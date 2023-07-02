use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zip::write::FileOptions as ZipFileOptions;

mod password;
pub mod password_generation;

pub use password::PasswordItem;
pub use password::SecurityQuestion;

struct ItemInMemory {
    mimetype: String,
    hidden: bool,
    updated_data: Option<Vec<u8>>,
}

struct ItemSerializer<'a>(&'a HashMap<String, ItemInMemory>);

impl Serialize for ItemSerializer<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;

        #[derive(Serialize)]
        struct ItemSerializer<'a> {
            #[serde(rename = "type")]
            mimetype: &'a str,
            #[serde(skip_serializing_if = "is_false")]
            hidden: bool,
        }

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.0 {
            let item = ItemSerializer {
                mimetype: &v.mimetype,
                hidden: v.hidden,
            };
            map.serialize_entry(k, &item)?;
        }
        map.end()
    }
}

type EncryptedZipArchiveFile = zip::ZipArchive<age::stream::StreamReader<File>>;

/// An encrypted keyring containing credentials & other sensitive data.
pub struct Keyring {
    path: PathBuf,
    password: Secret,
    /// Items which are on the keyring. Metadata is always in memory for an open keyring, contents
    /// are if they are not yet written out.
    items: HashMap<String, ItemInMemory>,
    /// Items which have been deleted from the in-memory version of the keyring, but still need to
    /// be purged from the underlying ZIP.
    deleted_items: HashSet<String>,
    zip_archive: Option<EncryptedZipArchiveFile>,
}

impl Keyring {
    /// Create a new keyring at the given path, with the given password.
    pub fn create(path: PathBuf, password: Secret) -> Result<Keyring, KeyringError> {
        let file = File::options()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(KeyringErrorRepr::Io)?;
        let mut keyring = Keyring {
            path,
            password,
            items: HashMap::new(),
            deleted_items: HashSet::new(),
            zip_archive: None,
        };
        keyring.save_into(file)?;
        Ok(keyring)
    }

    /// Load the keyring at the given path with the given password.
    pub fn load(path: PathBuf, password: Secret) -> Result<Keyring, KeyringError> {
        let mut zip_archive = Self::load_zip_archive(&path, &password)?;
        let magic_file = zip_archive
            .by_name("META-INF/MAGIC")
            .map_err(KeyringErrorRepr::ZipReadErr)?;
        verify_magic(magic_file)?;
        let contents = zip_archive
            .by_name("META-INF/CONTENTS")
            .map_err(KeyringErrorRepr::ZipReadErr)?;
        let items = load_contents(contents)?;
        Ok(Keyring {
            path,
            password,
            items,
            deleted_items: HashSet::new(),
            zip_archive: Some(zip_archive),
        })
    }

    fn load_zip_archive(
        path: &Path,
        password: &Secret,
    ) -> Result<EncryptedZipArchiveFile, KeyringError> {
        let file = File::open(&path).map_err(KeyringErrorRepr::Io)?;
        let decryptor =
            match age::Decryptor::new(file).map_err(KeyringErrorRepr::DecryptionError)? {
                age::Decryptor::Recipients(_) => {
                    return Err(KeyringErrorRepr::UnexpectedNonPasswordAgeData.into())
                }
                age::Decryptor::Passphrase(pd) => pd,
            };
        // FIXME: how to let the user control the work factor value, here?
        let decryptor = decryptor
            .decrypt(&password.0.clone().into(), Some(20))
            .map_err(KeyringErrorRepr::DecryptionError)?;
        Ok(zip::ZipArchive::new(decryptor).map_err(KeyringErrorRepr::ZipReadErr)?)
    }

    pub fn save(&mut self) -> Result<(), KeyringError> {
        let temp_path = {
            let parent = self.path.parent().unwrap();
            let mut file_name = self.path.file_name().unwrap().to_os_string();
            file_name.push(".writing");
            parent.join(file_name)
        };

        let file = File::options()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .map_err(KeyringErrorRepr::Io)?;

        self.save_into(file)?;
        fs::rename(temp_path, &self.path).map_err(KeyringErrorRepr::Io)?;
        self.zip_archive = Some(Self::load_zip_archive(&self.path, &self.password)?);
        for item in self.items.values_mut() {
            item.updated_data = None;
        }
        Ok(())
    }

    fn save_into(&mut self, file: File) -> Result<(), KeyringError> {
        let encryptor = age::Encryptor::with_user_passphrase(self.password.0.clone().into());

        // ZIP writing requires Seek (to update the file headers as the archive is written) but the
        // age writer isn't `Seek`.
        let zip_data = {
            let mut data = Vec::new();
            let mut zip_writer = zip::ZipWriter::new(io::Cursor::new(&mut data));
            if let Some(existing_archive) = self.zip_archive.as_mut() {
                // Re-encode the existing ZIP entires.
                // Skip our META-INF stuff, as we'll re-write them, as well as anything with
                // updates.
                let should_skip = |name: &str| -> bool {
                    match name {
                        "META-INF/MAGIC" => true,
                        "META-INF/CONTENTS" => true,
                        _ => match name.strip_prefix("items/") {
                            Some(item_name) => {
                                let was_updated = self
                                    .items
                                    .get(item_name)
                                    .map(|item| item.updated_data.is_some())
                                    .unwrap_or(false);
                                if was_updated {
                                    return true;
                                }

                                self.deleted_items.contains(item_name)
                            }
                            None => false,
                        },
                    }
                };
                for idx in 0..existing_archive.len() {
                    let file = existing_archive
                        .by_index_raw(idx)
                        .map_err(KeyringErrorRepr::ZipReadErr)?;
                    if !should_skip(file.name()) {
                        zip_writer
                            .raw_copy_file(file)
                            .map_err(KeyringErrorRepr::ZipWriteErr)?;
                    }
                }
            }

            // Write any entries requiring an update:
            for (name, item) in self.items.iter() {
                let updated_data = match item.updated_data.as_ref() {
                    Some(d) => d,
                    None => continue,
                };
                zip_writer
                    .start_file(&format!("items/{}", name), ZipFileOptions::default())
                    .map_err(KeyringErrorRepr::ZipWriteErr)?;
                zip_writer
                    .write_all(updated_data)
                    .map_err(KeyringErrorRepr::Io)?;
            }

            // Write the MAGIC file:
            zip_writer
                .start_file(
                    "META-INF/MAGIC",
                    ZipFileOptions::default().compression_method(zip::CompressionMethod::Stored),
                )
                .map_err(KeyringErrorRepr::ZipWriteErr)?;
            zip_writer
                .write_all(MAGIC.as_bytes())
                .map_err(KeyringErrorRepr::Io)?;

            // Write the CONTENTS file:
            zip_writer
                .start_file("META-INF/CONTENTS", ZipFileOptions::default())
                .map_err(KeyringErrorRepr::ZipWriteErr)?;
            serde_json::to_writer(&mut zip_writer, &ItemSerializer(&self.items))
                .map_err(KeyringErrorRepr::SerializationFailure)?;

            zip_writer.finish().map_err(KeyringErrorRepr::ZipWriteErr)?;
            drop(zip_writer);
            data
        };

        let mut writer = encryptor
            .wrap_output(file)
            .map_err(KeyringErrorRepr::EncryptionError)?;
        writer.write_all(&zip_data).map_err(KeyringErrorRepr::Io)?;
        writer.finish().map_err(KeyringErrorRepr::Io)?;
        Ok(())
    }

    pub fn item_metadata(&self) -> impl Iterator<Item = ItemMetadata<'_>> {
        self.items.iter().map(|(k, v)| ItemMetadata {
            name: k,
            mimetype: &v.mimetype,
        })
    }

    pub fn has_item(&self, with_name: &str) -> bool {
        self.items.contains_key(with_name)
    }

    pub fn set_item<I: KeyringItem>(&mut self, name: String, item: I) -> Result<(), KeyringError> {
        let new_item = ItemInMemory {
            mimetype: I::mimetype().to_owned(),
            hidden: false,
            updated_data: Some(
                item.serialize()
                    .map_err(KeyringErrorRepr::ItemSerializationError)?,
            ),
        };
        self.deleted_items.remove(&name);
        self.items.insert(name, new_item);
        Ok(())
    }

    /// Delete an item from the keyring.
    ///
    /// Returns `true` if the item existed, and was deleted, or `false` if that item didn't exist,
    /// and nothing was deleted.
    pub fn delete_item(&mut self, name: String) -> bool {
        match self.items.remove(&name) {
            Some(_) => {
                self.deleted_items.insert(name);
                true
            }
            None => false,
        }
    }

    /// Get an item from the keyring.
    ///
    /// Returns `None` if the item didn't exist, or was of the wrong mimetype.
    pub fn get_item<T: KeyringItem>(&mut self, name: &str) -> Result<Option<T>, KeyringError> {
        let raw_item = match self.get_item_raw(name)? {
            Some(s) => s,
            None => return Ok(None),
        };
        if raw_item.mimetype == T::mimetype() {
            Ok(Some(
                T::deserialize(&raw_item.data).map_err(KeyringErrorRepr::ItemDeserializationError)?,
            ))
        } else {
            Ok(None)
        }
    }

    pub fn get_item_raw(&mut self, name: &str) -> Result<Option<Item>, KeyringError> {
        let item_in_mem = match self.items.get(name) {
            Some(i) => i,
            None => return Ok(None),
        };
        if let Some(data) = item_in_mem.updated_data.as_deref() {
            Ok(Some(Item {
                mimetype: &item_in_mem.mimetype,
                data: Cow::from(data),
            }))
        } else {
            let zip_item_name = format!("items/{}", name);
            let mut item = self
                .zip_archive
                .as_mut()
                .unwrap()
                .by_name(&zip_item_name)
                .map_err(KeyringErrorRepr::ZipReadErr)?;
            let mut item_data = Vec::new();
            item.read_to_end(&mut item_data)
                .map_err(KeyringErrorRepr::Io)?;
            Ok(Some(Item {
                mimetype: &item_in_mem.mimetype,
                data: Cow::from(item_data),
            }))
        }
    }

    pub fn set_item_raw(&mut self, name: String, item: ItemOwned) -> Result<(), KeyringError> {
        let new_item = ItemInMemory {
            mimetype: item.mimetype,
            hidden: false,
            updated_data: Some(item.data),
        };
        self.deleted_items.remove(&name);
        self.items.insert(name, new_item);
        Ok(())
    }
}

pub struct Item<'a> {
    pub mimetype: &'a str,
    pub data: Cow<'a, [u8]>,
}

pub struct ItemOwned {
    pub mimetype: String,
    pub data: Vec<u8>,
}

pub struct ItemMetadata<'a> {
    pub name: &'a str,
    pub mimetype: &'a str,
}

pub trait KeyringItem {
    fn mimetype() -> &'static str;
    fn serialize(&self) -> Result<Vec<u8>, anyhow::Error>;
    fn deserialize(data: &[u8]) -> Result<Self, anyhow::Error>
    where
        Self: Sized;
}

impl<T: KeyringItem> KeyringItem for &T {
    fn mimetype() -> &'static str {
        T::mimetype()
    }

    fn serialize(&self) -> Result<Vec<u8>, anyhow::Error> {
        (*self).serialize()
    }

    fn deserialize(data: &[u8]) -> Result<Self, anyhow::Error> {
        // TODO: this is a bit ugly; is there a better way here?
        panic!("cannot deserialize a ref");
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct KeyringError(KeyringErrorRepr);

impl From<KeyringErrorRepr> for KeyringError {
    fn from(err: KeyringErrorRepr) -> KeyringError {
        KeyringError(err)
    }
}

#[derive(Debug, thiserror::Error)]
enum KeyringErrorRepr {
    #[error("I/O error: {0}")]
    Io(io::Error),
    #[error("failed to decode the outer layer of the encrypted data: {0}")]
    OuterLayerDecodeFailed(serde_json::Error),
    #[error("failed to serialize the outer layer of the keyring into JSON: {0}")]
    SerializationFailure(serde_json::Error),
    #[error("encryption error: {0}")]
    EncryptionError(age::EncryptError),
    #[error("decryption error: {0}")]
    DecryptionError(age::DecryptError),
    #[error(
        "the encrypted data (an \"age\" file) was encrypted to particular asymmetric keys, whereas \
         it is expected to be encrypted with a passphrase"
    )]
    UnexpectedNonPasswordAgeData,
    #[error("error while writing ZIP archive: {0}")]
    ZipWriteErr(#[source] zip::result::ZipError),
    #[error("error while reading ZIP archive: {0}")]
    ZipReadErr(#[source] zip::result::ZipError),
    #[error("not a keyring file (the magic did not match)")]
    BadMagic,
    #[error("failed to serialize item: {0}")]
    ItemSerializationError(#[source] anyhow::Error),
    #[error("failed to deserialize item: {0}")]
    ItemDeserializationError(#[source] anyhow::Error),
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Secret(String);

opaque_debug::implement!(Secret);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Secret {
        Secret(s)
    }
}

static MAGIC: &str = "application/prs.thanatos.keyring";

fn verify_magic(mut rdr: impl Read) -> Result<(), KeyringErrorRepr> {
    // Must be longer than the magic string.
    let mut buf = [0u8; 64];

    let mut length_read = 0;
    loop {
        let this_read = rdr
            .read(&mut buf[length_read..])
            .map_err(KeyringErrorRepr::Io)?;
        if this_read == 0 {
            break;
        }
        length_read += this_read;
        if length_read == buf.len() {
            // Because `buf` is longer than the magic, we've read too many bytes, so it isn't a
            // match.
            return Err(KeyringErrorRepr::BadMagic);
        }
    }
    if &buf[..length_read] == MAGIC.as_bytes() {
        Ok(())
    } else {
        Err(KeyringErrorRepr::BadMagic)
    }
}

fn load_contents(rdr: impl Read) -> Result<HashMap<String, ItemInMemory>, KeyringErrorRepr> {
    let items: ContentsDeserializer =
        serde_json::from_reader(rdr).map_err(KeyringErrorRepr::OuterLayerDecodeFailed)?;
    Ok(items.0)
}

struct ContentsDeserializer(HashMap<String, ItemInMemory>);

impl<'de> Deserialize<'de> for ContentsDeserializer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(ContentsDeserializer(
            deserializer.deserialize_map(ContentsMapVisitor)?,
        ))
    }
}

struct ContentsMapVisitor;

impl<'de> serde::de::Visitor<'de> for ContentsMapVisitor {
    type Value = HashMap<String, ItemInMemory>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a map for the keyring contents")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        let mut map = HashMap::with_capacity(access.size_hint().unwrap_or(0));

        #[derive(Deserialize)]
        struct ContentsItem {
            #[serde(rename = "type")]
            mimetype: String,
            #[serde(default)]
            hidden: bool,
        }

        while let Some((key, value)) = access.next_entry()? {
            let item: ContentsItem = value;
            let real_item = ItemInMemory {
                mimetype: item.mimetype,
                hidden: item.hidden,
                updated_data: None,
            };
            map.insert(key, real_item);
        }

        Ok(map)
    }
}

fn is_false(b: &bool) -> bool {
    !b
}
