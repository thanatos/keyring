//! Base operations on a keyring, which are agnostic of the type of item they are operating on.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Context;

use crate::{load_keyring, or_default_keyring, ProgError};

pub(crate) fn init_keyring(keyring_path: Option<PathBuf>) -> Result<(), ProgError> {
    let keyring_path = or_default_keyring(keyring_path)?;
    eprintln!("Creating a new keyring at {}", keyring_path.display());
    let password = keyring::Secret::from(
        rpassword::prompt_password("    New password: ")
            .context("failed to read password from TTY")?,
    );
    let confirm_password = keyring::Secret::from(
        rpassword::prompt_password("Confirm password: ")
            .context("failed to read password from TTY")?,
    );
    if password != confirm_password {
        return Err(ProgError::InitPasswordsDidntMatch);
    }
    keyring::Keyring::create(keyring_path.clone(), password)?;
    eprintln!("New keyring created at {}", keyring_path.display());
    Ok(())
}

pub(crate) fn remove_keyring_item(keyring_path: Option<PathBuf>) -> Result<(), ProgError> {
    let mut keyring = load_keyring(keyring_path)?;
    let selected_item = crate::select::select_item(&keyring)?.to_owned();
    eprintln!(
        "This will delete the item named {:?} from the keyring.",
        selected_item
    );
    let confirm_delete = dialoguer::Confirm::new()
        .with_prompt("Delete?")
        .default(false)
        .interact()
        .context("failed to prompt you, somehow")?;
    if confirm_delete {
        let was_deleted = keyring.delete_item(selected_item);
        assert!(was_deleted);
        keyring.save()?;
        Ok(())
    } else {
        Err(ProgError::DeleteAborted)
    }
}

pub(crate) fn list_keyring(keyring_path: Option<PathBuf>) -> Result<(), ProgError> {
    let keyring = load_keyring(keyring_path)?;

    struct RowMetadata<'a>(keyring::ItemMetadata<'a>);

    impl crate::table::TableDisplay for RowMetadata<'_> {
        type Item = String;

        fn columns() -> usize {
            2
        }

        fn column_name(column_index: usize) -> &'static str {
            match column_index {
                0 => "Item name",
                1 => "Item mimetype",
                _ => panic!(),
            }
        }

        fn item(&self, column_index: usize) -> &str {
            match column_index {
                0 => self.0.name,
                1 => self.0.mimetype,
                _ => panic!(),
            }
        }
    }

    let rows = keyring.item_metadata().map(RowMetadata).collect::<Vec<_>>();
    crate::table::display_table(&rows, std::io::stdout()).context("failed to output table")?;

    Ok(())
}

pub(crate) fn edit_keyring_item(keyring_path: Option<PathBuf>) -> Result<(), ProgError> {
    let mut keyring = load_keyring(keyring_path)?;
    let selected_item = crate::select::select_item(&keyring)?.to_owned();

    let raw_item = keyring
        .get_item_raw(&selected_item)?
        .expect("the selected item should always exist on the keyring");
    let item_under_edit = crate::import_export::encode_raw_item_as_yaml(&selected_item, &raw_item);

    let mut temp_file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .context("failed to create temporary file, prior to opening it in your editor")?;

    serde_yaml::to_writer(&mut temp_file, &item_under_edit)
        .context("failed to write item to temporary file")?;
    temp_file
        .flush()
        .context("failed to flush item to temporary file")?;

    let item_under_edit = loop {
        let item_under_edit = crate::editor::run_editor_yaml::<crate::import_export::YamlItem, _>(
            &mut temp_file,
            |err| {
                anyhow::Error::new(err)
                    .context("failed to parse result as an edited item")
                    .into()
            },
        )?;

        // Detect if the item is being renamed:
        if item_under_edit.name != selected_item {
            // If there's already an item under the new name, deny the rename. We force the user to
            // remove the item first, to prevent mistakes.
            if keyring.has_item(&item_under_edit.name) {
                eprintln!(
                    "There already exists an item under the new name for this item.\n\
                     This command refuses to overwrite the item; best that you back out and \
                     inspect the situation. If you want to replace the other item, inspect it, \
                     delete it, and then retry the rename."
                );
                let edit_again = dialoguer::Confirm::new()
                    .with_prompt("Edit again?")
                    .default(true)
                    .interact()
                    .context("failed to prompt you, somehow")?;
                if edit_again {
                    continue;
                } else {
                    return Err(crate::ProgError::EditingCancelled);
                }
            }
        }
        break item_under_edit;
    };

    if item_under_edit.name != selected_item {
        unimplemented!("need to get around to renames…");
    }

    let item_data_encoded = item_under_edit.encode_data()?;
    crate::import_export::validate_item(
        &item_under_edit.name,
        &item_under_edit.mimetype,
        &item_data_encoded,
    )?;
    let keyring_item = keyring::ItemOwned {
        mimetype: item_under_edit.mimetype,
        data: item_data_encoded,
    };
    keyring.set_item_raw(item_under_edit.name, keyring_item)?;
    keyring.save()?;
    Ok(())
}

pub(crate) fn get_keyring_item(keyring_path: Option<PathBuf>) -> Result<(), ProgError> {
    let mut keyring = load_keyring(keyring_path)?;
    let selected_item = crate::select::select_item(&keyring)?.to_owned();
    let item = keyring.get_item_raw(&selected_item)?.unwrap();
    let item = crate::import_export::encode_raw_item_as_yaml(&selected_item, &item);
    {
        let stdout = io::stdout().lock();
        serde_yaml::to_writer(stdout, &item).context("failed to write item as YAML to stdout")?;
    }
    Ok(())
}
