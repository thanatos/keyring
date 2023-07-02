use std::borrow::Cow;
use std::env;
use std::ffi::OsStr;
use std::io::{self, Seek};
use std::path::Path;
use std::process::Command;

use anyhow::Context;

pub(crate) fn run_editor(path: &Path) -> Result<(), crate::ProgError> {
    let editor = env::var_os("EDITOR")
        .map(Cow::from)
        .unwrap_or_else(|| Cow::from(OsStr::new("vim")));
    let mut cmd = Command::new(&editor);
    cmd.arg(path);
    let exit_status = cmd
        .spawn()
        .with_context(|| {
            format!(
                "failed to start your editor (`{}`)",
                editor.to_string_lossy()
            )
        })?
        .wait()
        .with_context(|| {
            format!(
                "failed to wait for your editor (`{}`) to finish",
                editor.to_string_lossy()
            )
        })?;
    if exit_status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "your editor (`{}`) exited with {}",
            editor.to_string_lossy(),
            exit_status
        )
        .into())
    }
}

pub(crate) fn run_editor_yaml<T: serde::de::DeserializeOwned, EF>(
    mut temp_file: &mut tempfile::NamedTempFile,
    serde_err_context: EF,
) -> Result<T, crate::ProgError>
where
    EF: Fn(serde_yaml::Error) -> crate::ProgError,
{
    loop {
        run_editor(temp_file.path())?;

        temp_file
            .seek(io::SeekFrom::Start(0))
            .context("failed to seek in temporary file")?;
        let value = match serde_yaml::from_reader::<_, T>(&mut temp_file) {
            Ok(v) => return Ok(v),
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
                    return Err(serde_err_context(err));
                }
            }
        };
    }
}
