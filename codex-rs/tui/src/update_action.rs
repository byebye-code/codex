/// Update action the CLI should perform after the TUI exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateAction {
    /// Update via `npm install -g @88code/codex@latest`.
    NpmGlobalLatest,
    /// Update via `bun install -g @88code/codex@latest`.
    BunGlobalLatest,
}

impl UpdateAction {
    /// Returns the list of command-line arguments for invoking the update.
    pub fn command_args(self) -> (&'static str, &'static [&'static str]) {
        match self {
            UpdateAction::NpmGlobalLatest => ("npm", &["install", "-g", "@88code/codex"]),
            UpdateAction::BunGlobalLatest => ("bun", &["install", "-g", "@88code/codex"]),
        }
    }

    /// Returns string representation of the command-line arguments for invoking the update.
    pub fn command_str(self) -> String {
        let (command, args) = self.command_args();
        shlex::try_join(std::iter::once(command).chain(args.iter().copied()))
            .unwrap_or_else(|_| format!("{command} {}", args.join(" ")))
    }
}

#[cfg(not(debug_assertions))]
pub(crate) fn get_update_action() -> Option<UpdateAction> {
    let managed_by_bun = std::env::var_os("CODEX_MANAGED_BY_BUN").is_some();

    detect_update_action(managed_by_bun)
}

#[cfg(any(not(debug_assertions), test))]
fn detect_update_action(managed_by_bun: bool) -> Option<UpdateAction> {
    if managed_by_bun {
        Some(UpdateAction::BunGlobalLatest)
    } else {
        // 88code: Default to npm update
        Some(UpdateAction::NpmGlobalLatest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_update_action_without_env_mutation() {
        // Default to npm
        assert_eq!(
            detect_update_action(false),
            Some(UpdateAction::NpmGlobalLatest)
        );
        // Bun if env var is set
        assert_eq!(
            detect_update_action(true),
            Some(UpdateAction::BunGlobalLatest)
        );
    }
}
