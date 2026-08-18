use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Write};
use std::path::{Path, PathBuf};

pub const GAME_PROFILE_SELECTION_FILE: &str = "game-profile-selection.json";
const GAME_PROFILE_SELECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GameProfileSelection {
    pub schema_version: u32,
    pub selected_profile_id: Option<String>,
}

impl Default for GameProfileSelection {
    fn default() -> Self {
        Self {
            schema_version: GAME_PROFILE_SELECTION_SCHEMA_VERSION,
            selected_profile_id: None,
        }
    }
}

impl GameProfileSelection {
    pub fn selected(profile_id: impl Into<String>) -> Self {
        Self {
            selected_profile_id: Some(profile_id.into()),
            ..Self::default()
        }
    }
}

pub fn game_profile_selection_path(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(GAME_PROFILE_SELECTION_FILE)
}

pub fn load_game_profile_selection(
    state_dir: impl AsRef<Path>,
) -> std::io::Result<GameProfileSelection> {
    let path = game_profile_selection_path(state_dir);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let bytes = std::fs::read(&path)?;
            let selection: GameProfileSelection =
                serde_json::from_slice(&bytes).map_err(|error| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("failed to parse game profile selection: {error}"),
                    )
                })?;
            if selection.schema_version != GAME_PROFILE_SELECTION_SCHEMA_VERSION {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "unsupported game profile selection schema {}; expected {}",
                        selection.schema_version, GAME_PROFILE_SELECTION_SCHEMA_VERSION
                    ),
                ));
            }
            Ok(selection)
        }
        Ok(_) => Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "game profile selection path {} is not a regular file",
                path.display()
            ),
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(GameProfileSelection::default()),
        Err(error) => Err(error),
    }
}

pub fn store_game_profile_selection(
    state_dir: impl AsRef<Path>,
    selection: &GameProfileSelection,
) -> std::io::Result<PathBuf> {
    if selection.schema_version != GAME_PROFILE_SELECTION_SCHEMA_VERSION {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "cannot store an unsupported game profile selection schema",
        ));
    }

    let state_dir = state_dir.as_ref();
    std::fs::create_dir_all(state_dir)?;
    let path = game_profile_selection_path(state_dir);
    let bytes = serde_json::to_vec_pretty(selection).map_err(|error| {
        Error::new(
            ErrorKind::InvalidData,
            format!("failed to serialize game profile selection: {error}"),
        )
    })?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = state_dir.join(format!(
        ".{GAME_PROFILE_SELECTION_FILE}.{}.{}.tmp",
        std::process::id(),
        nonce
    ));

    let write_result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp_path, &path)
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result.map(|()| path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_round_trip_and_clear_are_durable() {
        let temp = tempfile::tempdir().unwrap();
        let selected = GameProfileSelection::selected("factorio");

        store_game_profile_selection(temp.path(), &selected).unwrap();
        assert_eq!(load_game_profile_selection(temp.path()).unwrap(), selected);

        store_game_profile_selection(temp.path(), &GameProfileSelection::default()).unwrap();
        assert_eq!(
            load_game_profile_selection(temp.path()).unwrap(),
            GameProfileSelection::default()
        );
    }

    #[cfg(unix)]
    #[test]
    fn selection_load_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.json");
        std::fs::write(&target, b"{}").unwrap();
        symlink(&target, game_profile_selection_path(temp.path())).unwrap();

        let error = load_game_profile_selection(temp.path()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }
}
