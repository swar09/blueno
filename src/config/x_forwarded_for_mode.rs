use serde::Deserialize;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum XForwardedForMode {
    #[default]
    Append,
    Replace,
    Off,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Holder {
        mode: XForwardedForMode,
    }

    fn parse(mode: &str) -> Result<XForwardedForMode, toml::de::Error> {
        toml::from_str::<Holder>(&format!("mode = \"{mode}\"")).map(|holder| holder.mode)
    }

    #[test]
    fn default_is_append() {
        assert_eq!(XForwardedForMode::default(), XForwardedForMode::Append);
    }

    #[test]
    fn every_mode_parses() {
        assert_eq!(parse("append").expect("parses"), XForwardedForMode::Append);
        assert_eq!(
            parse("replace").expect("parses"),
            XForwardedForMode::Replace
        );
        assert_eq!(parse("off").expect("parses"), XForwardedForMode::Off);
    }

    #[test]
    fn unknown_mode_is_rejected() {
        assert!(parse("bogus").is_err());
        assert!(parse("Append").is_err());
    }
}
