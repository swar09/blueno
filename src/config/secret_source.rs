use std::fs;

use crate::config::SecretError;

pub fn read_secret(var: &str) -> Result<Option<String>, SecretError> {
    read_secret_with(var, |name| std::env::var(name).ok())
}

pub fn read_secret_with(
    var: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<String>, SecretError> {
    let direct = lookup(var).filter(|value| !value.is_empty());
    let file_var = format!("{var}_FILE");
    let file_path = lookup(&file_var).filter(|value| !value.is_empty());

    match (direct, file_path) {
        (Some(_), Some(_)) => Err(SecretError::BothSet {
            var: var.to_string(),
        }),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => {
            let content = fs::read_to_string(&path).map_err(|source| SecretError::FileRead {
                path: path.clone(),
                source,
            })?;
            let trimmed = trim_single_newline(&content);
            Ok(Some(trimmed.to_string()).filter(|value| !value.is_empty()))
        }
        (None, None) => Ok(None),
    }
}

fn trim_single_newline(content: &str) -> &str {
    content
        .strip_suffix("\r\n")
        .or_else(|| content.strip_suffix('\n'))
        .unwrap_or(content)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::*;

    fn lookup_from(pairs: Vec<(&str, String)>) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blueno-secret-source-{}-{}",
            std::process::id(),
            name
        ))
    }

    #[test]
    fn reads_direct_variable() {
        let lookup = lookup_from(vec![("TOKEN", "abc".to_string())]);
        let value = read_secret_with("TOKEN", lookup).expect("read");
        assert_eq!(value.as_deref(), Some("abc"));
    }

    #[test]
    fn reads_file_and_trims_one_trailing_newline() {
        let path = temp_path("trim_lf");
        fs::write(&path, "abc\n\n").expect("write");
        let lookup = lookup_from(vec![("TOKEN_FILE", path.display().to_string())]);
        let value = read_secret_with("TOKEN", lookup).expect("read");
        assert_eq!(value.as_deref(), Some("abc\n"));
        fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn reads_file_and_trims_crlf() {
        let path = temp_path("trim_crlf");
        fs::write(&path, "abc\r\n").expect("write");
        let lookup = lookup_from(vec![("TOKEN_FILE", path.display().to_string())]);
        let value = read_secret_with("TOKEN", lookup).expect("read");
        assert_eq!(value.as_deref(), Some("abc"));
        fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn both_set_is_an_error() {
        let lookup = lookup_from(vec![
            ("TOKEN", "abc".to_string()),
            ("TOKEN_FILE", "/nonexistent".to_string()),
        ]);
        let error = read_secret_with("TOKEN", lookup).expect_err("both set");
        assert!(matches!(error, SecretError::BothSet { ref var } if var == "TOKEN"));
    }

    #[test]
    fn missing_file_reports_path() {
        let path = temp_path("missing");
        let lookup = lookup_from(vec![("TOKEN_FILE", path.display().to_string())]);
        let error = read_secret_with("TOKEN", lookup).expect_err("missing file");
        match error {
            SecretError::FileRead { path: reported, .. } => {
                assert_eq!(reported, path.display().to_string());
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn empty_values_are_treated_as_unset() {
        let lookup = lookup_from(vec![
            ("TOKEN", String::new()),
            ("TOKEN_FILE", String::new()),
        ]);
        let value = read_secret_with("TOKEN", lookup).expect("read");
        assert_eq!(value, None);
    }

    #[test]
    fn empty_file_is_treated_as_unset() {
        let path = temp_path("empty");
        fs::write(&path, "\n").expect("write");
        let lookup = lookup_from(vec![("TOKEN_FILE", path.display().to_string())]);
        let value = read_secret_with("TOKEN", lookup).expect("read");
        assert_eq!(value, None);
        fs::remove_file(&path).expect("cleanup");
    }

    #[test]
    fn unset_returns_none() {
        let value = read_secret_with("TOKEN", |_| None).expect("read");
        assert_eq!(value, None);
    }
}
