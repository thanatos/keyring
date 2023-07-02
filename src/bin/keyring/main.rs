use std::env;
use std::path::PathBuf;
use std::process;

use anyhow::Context;
use clap::Parser;

mod base_operations;
mod editor;
mod import_export;
mod pw;
mod select;
mod table;

#[derive(Parser)]
enum Args {
    /// Create a new keyring file.
    Init {
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
    /// Remove an item from a keyring.
    Remove {
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
    /// List items contained on the keyring.
    List {
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
    /// Edit the raw data for an item.
    Edit {
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
    /// Get the raw data for an item on the keyring.
    Get {
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
    /// Import items into the keyring.
    Import {
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
    /// Commands for dealing with password items.
    #[command(subcommand)]
    Password(PasswordCommand),
}

#[derive(clap::Subcommand)]
#[command(alias = "pw")]
enum PasswordCommand {
    New {
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
    /// Generate a new password, and edit the result in your editor to collect additional details
    /// such as the item name, the username, or the security questions. The saved result is then
    /// stored in the keyring.
    EditNew {
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
    /// Copy a password item's password to the clipboard.
    Copy {
        #[arg(long)]
        keyring: Option<PathBuf>,
    },
}

fn run() -> Result<(), ProgError> {
    let args = Args::parse();

    match args {
        Args::Init { keyring } => base_operations::init_keyring(keyring)?,
        Args::Remove { keyring } => base_operations::remove_keyring_item(keyring)?,
        Args::List { keyring } => base_operations::list_keyring(keyring)?,
        Args::Edit { keyring } => base_operations::edit_keyring_item(keyring)?,
        Args::Get { keyring } => base_operations::get_keyring_item(keyring)?,
        Args::Import { keyring } => import_export::import(keyring)?,
        Args::Password(PasswordCommand::New { keyring }) => unimplemented!(),
        Args::Password(PasswordCommand::EditNew { keyring }) => {
            pw::edit_new_password(keyring)?;
        }
        Args::Password(PasswordCommand::Copy { keyring }) => pw::copy_password(keyring)?,
    }

    Ok(())
}

fn main() {
    match run() {
        Ok(()) => (),
        Err(ProgError::Keyring(err)) => panic!("{err:?}"),
        Err(ProgError::Other(err)) => panic!("{err:?}"),
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }
}

fn or_default_keyring(keyring_path: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match keyring_path {
        Some(p) => Ok(p),
        None => default_keyring(),
    }
}

fn default_keyring() -> anyhow::Result<PathBuf> {
    let home = env::var_os("HOME")
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot find home directory of user"))?;
    let default_path = {
        let mut p = PathBuf::from(home);
        p.push(".keyring");
        p.push("keyring.v2");
        p
    };
    Ok(default_path)
}

fn load_keyring(keyring_path: Option<PathBuf>) -> Result<keyring::Keyring, ProgError> {
    let keyring_path = or_default_keyring(keyring_path)?;
    let password = keyring::Secret::from(
        rpassword::prompt_password("Password: ").context("failed to read password from TTY")?,
    );
    Ok(keyring::Keyring::load(keyring_path, password)?)
}

#[derive(Debug, thiserror::Error)]
enum ProgError {
    #[error("Passwords did not match.")]
    InitPasswordsDidntMatch,
    #[error("Item selection cancelled; exiting.")]
    ItemSelectionCancelled,
    #[error("Editing cancelled; exiting.")]
    EditingCancelled,
    #[error("Delete aborted; exiting.")]
    DeleteAborted,
    #[error(
        "The import contained an item whose name conflicts with an item already on the keyring: {0}"
    )]
    ImportDulicateItem(String),
    #[error("Failed to validate item named {0:?} during import: {1}")]
    ImportValidationFailed(String, #[source] anyhow::Error),
    #[error("The item named {0:?} was not a password item.")]
    NotAPasswordItem(String),
    #[error("Keyring error: {0}")]
    Keyring(keyring::KeyringError),
    #[error(transparent)]
    Other(anyhow::Error),
}

impl From<anyhow::Error> for ProgError {
    fn from(err: anyhow::Error) -> ProgError {
        ProgError::Other(err)
    }
}

impl From<keyring::KeyringError> for ProgError {
    fn from(err: keyring::KeyringError) -> ProgError {
        ProgError::Keyring(err)
    }
}
