use std::io;
use std::path::PathBuf;

use anyhow::Context;
use base64::Engine;
use serde::{Deserialize, Serialize};

use keyring::{KeyringItem, PasswordItem};
use crate::{load_keyring, ProgError};

pub(crate) fn import(keyring_path: Option<PathBuf>) -> Result<(), ProgError> {
    let mut keyring = load_keyring(keyring_path)?;
    let items_to_import = {
        let mut items = Vec::new();
        for document in serde_yaml::Deserializer::from_reader(io::stdin().lock()) {
            let item = YamlItem::deserialize(document)
                .context("failed to read YAML item from stdin")?;
            items.push(item);
        }
        items
    };

    // Ensure there aren't any conflicts. If there are, we just abort the import.
    for item in items_to_import.iter() {
        if keyring.has_item(&item.name) {
            return Err(ProgError::ImportDulicateItem(item.name.clone()));
        }
    }

    let number_of_items = items_to_import.len();
    for item in items_to_import {
        let data = item.encode_data()?;
        // Validate that the items decode:
        validate_item(&item.name, &item.mimetype, &data)?;
        let keyring_item = keyring::ItemOwned {
            mimetype: item.mimetype,
            data,
        };
        keyring.set_item_raw(item.name, keyring_item)?;
    }

    keyring.save()?;
    eprintln!("Imported {} items.", number_of_items);
    Ok(())
}

fn validate_item(name: &str, mimetype: &str, data: &[u8]) -> Result<(), ProgError> {
    match mimetype {
        m if m == PasswordItem::mimetype() => {
            if let Err(err) = serde_json::from_slice::<PasswordItem>(data) {
                return Err(ProgError::ImportValidationFailed(name.to_owned(), err.into()));
            }
        }
        "text/plain; charset=utf-8" => {
            if let Err(err) = std::str::from_utf8(data) {
                return Err(ProgError::ImportValidationFailed(name.to_owned(), err.into()));
            }
        }
        _ => eprintln!("Warning: unable to validate item {:?} with mimetype {}", name, mimetype),
    }
    Ok(())
}

pub(crate) fn encode_raw_item_as_yaml(item_name: &str, item: &keyring::Item) -> YamlItem {
    let (data_encoding, data) = match serde_json::from_slice(&item.data) {
        Ok(v) => (DataEncoding::Json, v),
        Err(_) => {
            let b64_data = serde_yaml::Value::String(
                base64::engine::general_purpose::STANDARD.encode(&item.data),
            );
            (DataEncoding::Base64, b64_data)
        }
    };
    YamlItem {
        name: item_name.to_owned(),
        mimetype: item.mimetype.to_owned(),
        data_encoding,
        data,
    }
}

/// What to encode the `data` part of a `YamlItem` item as:
/// * `Json`: `data` contains a YAML value that will be transcoded to JSON & stored on the keyring.
/// * `Base64`: `data` contains a string that will be de-base-64'd and stored.
#[derive(Deserialize, Serialize)]
pub(crate) enum DataEncoding {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "base64")]
    Base64,
}

/// An item from the keyring, represented as YAML. This is used both for import/export, and for
/// editing an entire item in one's `$EDITOR`.
#[derive(Deserialize, Serialize)]
pub(crate) struct YamlItem {
    pub name: String,
    pub mimetype: String,
    pub data_encoding: DataEncoding,
    pub data: serde_yaml::Value,
}

impl YamlItem {
    fn encode_data(&self) -> anyhow::Result<Vec<u8>> {
        match self.data_encoding {
            DataEncoding::Json => Ok(serde_json::to_string(&self.data)?.into_bytes()),
            DataEncoding::Base64 => {
                let data_as_string = match &self.data {
                    serde_yaml::Value::String(s) => s,
                    _ => anyhow::bail!("`data` should have contained a string, but didn't"),
                };
                let data = base64::engine::general_purpose::STANDARD
                    .decode(&data_as_string)
                    .context("`data` should have been base64, but wasn't")?;
                Ok(data)
            }
        }
    }
}
