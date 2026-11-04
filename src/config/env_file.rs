use std::path::Path;

use crate::config::SecretError;

pub fn load_env_file(path: impl AsRef<Path>) -> Result<(), SecretError> {
    let path = path.as_ref();
    dotenvy::from_path(path).map_err(|source| SecretError::EnvFile {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_an_env_file_error() {
        let path = std::env::temp_dir().join(format!(
            "blueno-env-file-missing-{}.env",
            std::process::id()
        ));
        let error = load_env_file(&path).expect_err("missing file");
        match error {
            SecretError::EnvFile { path: reported, .. } => {
                assert_eq!(reported, path.display().to_string());
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn parses_variables_without_touching_process_environment() {
        let path =
            std::env::temp_dir().join(format!("blueno-env-file-parse-{}.env", std::process::id()));
        std::fs::write(&path, "BLUENO_TEST_A=one\nBLUENO_TEST_B=\"two words\"\n").expect("write");
        let pairs: Vec<(String, String)> = dotenvy::from_path_iter(&path)
            .expect("open")
            .collect::<Result<_, _>>()
            .expect("parse");
        assert_eq!(
            pairs,
            vec![
                ("BLUENO_TEST_A".to_string(), "one".to_string()),
                ("BLUENO_TEST_B".to_string(), "two words".to_string()),
            ]
        );
        std::fs::remove_file(&path).expect("cleanup");
    }
}
