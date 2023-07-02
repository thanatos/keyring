use anyhow::Context;

pub(crate) fn select_item(keyring: &keyring::Keyring) -> Result<&str, crate::ProgError> {
    let items = {
        let mut items = keyring.item_metadata().map(|i| i.name).collect::<Vec<_>>();
        items.sort_unstable();
        items
    };
    let selection = dialoguer::FuzzySelect::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .items(&items)
        .interact_opt()
        .context("failed to query your selection")?
        .ok_or(crate::ProgError::ItemSelectionCancelled)?;

    Ok(items[selection])
}
