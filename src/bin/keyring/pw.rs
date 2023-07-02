use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::Context;
use serde::Deserialize;

use crate::{load_keyring, ProgError};
use keyring::{KeyringItem, PasswordItem};

fn create_password(keyring_path: Option<PathBuf>) -> anyhow::Result<()> {
    unimplemented!()
}

pub(crate) fn edit_new_password(keyring_path: Option<PathBuf>) -> Result<(), ProgError> {
    let mut keyring = crate::load_keyring(keyring_path)?;

    let mut rng = rand::thread_rng();
    let alphabet = {
        // TODO: make configurable
        let mut abc = Vec::new();
        abc.extend(LETTERS.chars());
        abc.extend(NUMBERS.chars());
        abc.extend(SYMBOLS.chars());
        abc
    };
    let new_password = keyring::password_generation::generate_random_password(
        &mut rng, &alphabet, // TODO: configurable
        16,
    );

    let mut temp_file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .context("failed to create temporary file, prior to opening it in your editor")?;

    let yaml_password = {
        let mut s = serde_yaml::to_string(&new_password).unwrap();
        assert!(s.pop() == Some('\n'));
        keyring::Secret::from(s)
    };

    let template = NEW_PW_TEMPLATE.replace("$PASSWORD", yaml_password.as_str());
    temp_file
        .write_all(template.as_bytes())
        .and_then(|()| temp_file.flush())
        .context(
            "failed to write template to temporary file, prior to opening it in your editor",
        )?;
    let parsed_item = loop {
        crate::editor::run_editor(temp_file.path())?;
        temp_file
            .seek(SeekFrom::Start(0))
            .context("failed to seek in temporary file")?;
        match serde_yaml::from_reader::<_, NewPasswordYaml>(&mut temp_file) {
            Ok(v) => {
                if keyring.has_item(&v.name) {
                    eprintln!("The keyring already contains an item named \"{}\"; what would you like to do?", v.name);
                    let items = &[
                        "Edit the item again",
                        "Replace the existing item with this one",
                        "Abort",
                    ];
                    let selection = dialoguer::FuzzySelect::with_theme(
                        &dialoguer::theme::ColorfulTheme::default(),
                    )
                    .items(&items[..])
                    .interact()
                    .context("failed to get your answer to a prompt")?;
                    match selection {
                        0 => continue,
                        1 => break v,
                        2 => return Err(anyhow::anyhow!("Aborted.").into()),
                        _ => panic!(),
                    }
                } else {
                    break v;
                }
            }
            Err(err) => {
                eprintln!("Failed to parse the result: {}", err);
                let edit_again = dialoguer::Confirm::new()
                    .with_prompt("Edit again?")
                    .default(true)
                    .interact()
                    .context("failed to prompt you, somehow")?;
                if edit_again {
                    continue;
                } else {
                    return Err(err)
                        .context("failed to parse new keyring item as a password item")
                        .map_err(|err| err.into());
                }
            }
        }
    };
    keyring.set_item(parsed_item.name, &parsed_item.spec)?;
    keyring.save()?;
    Ok(())
}

pub(crate) fn copy_password(keyring_path: Option<PathBuf>) -> Result<(), ProgError> {
    let mut keyring = load_keyring(keyring_path)?;
    let selected_item = crate::select::select_item(&keyring)?.to_owned();
    let raw_item = keyring
        .get_item_raw(&selected_item)?
        .expect("the selected item should always exist on the keyring");
    if raw_item.mimetype == PasswordItem::mimetype() {
        let password_item = <PasswordItem as keyring::KeyringItem>::deserialize(&raw_item.data)?;
        send_to_clipboard(password_item.password.as_str().as_bytes())?;
        eprintln!("Copied to the clipboard.");
        Ok(())
    } else {
        Err(ProgError::NotAPasswordItem(selected_item))
    }
}

fn send_to_clipboard(data: &[u8]) -> anyhow::Result<()> {
    let mut child = clipboard_cmd()
        .stdin(Stdio::piped())
        .spawn()?;
    child.stdin.as_mut().unwrap().write_all(data)?;
    child.wait()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn clipboard_cmd() -> Command {
    Command::new("pbcopy")
}

#[cfg(not(target_os = "macos"))]
fn clipboard_cmd() -> Command {
    let mut cmd = Command::new("xsel");
    cmd.arg("-b");
    cmd
}

#[derive(Deserialize)]
struct NewPasswordYaml {
    name: String,
    spec: keyring::PasswordItem,
}

static NEW_PW_TEMPLATE: &str = r#"name:  # the name of the new item
spec:
  # username:
  # email:
  password: $PASSWORD
  # security_questions:
  #   - q:
  #     a:
"#;

static LETTERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static NUMBERS: &str = "0123456789";
static SYMBOLS: &str = "~!@#$%^&*-_:;,.?";
static MORE_SYMBOLS: &str = "`\'\"\\/{}[]()<>";
