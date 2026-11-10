use blueno::config::{AuthMode, ConfigError, GatewayConfig};

pub const HELP: &str = "blueno api gateway\n\nusage: blueno [options]\n\noptions:\n  -c, --config <file>     path to configuration file (default: conf/blueno.toml)\n      --host <host>       server bind host\n  -p, --port <port>       server bind port\n      --auth <bool>       enable or disable authentication\n      --no-auth           disable authentication\n      --auth-mode <mode>  auth mode: secret | jwks | none\n      --env-file <file>   load environment variables from a .env file (also BLUENO_ENV_FILE)\n      --jwks <url>        jwks well-known endpoint\n      --logout-path <path> auth logout endpoint path\n      --redis <url>       redis coordinator url\n      --rate-limit <bool> enable or disable rate limiter\n      --rate-limit-script <file> custom redis lua script (default: built-in)\n  -h, --help              print help information";

#[derive(Debug, Default)]
pub struct Cli {
    pub help: bool,
    pub config_path: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub auth_enabled: Option<bool>,
    pub auth_mode: Option<AuthMode>,
    pub env_file: Option<String>,
    pub jwks_endpoint: Option<String>,
    pub logout_path: Option<String>,
    pub redis_url: Option<String>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_script: Option<String>,
}

impl Cli {
    pub fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        Self::parse_from(&args)
    }

    pub fn parse_from(args: &[String]) -> Self {
        let mut cli = Self::default();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--help" | "-h" => {
                    cli.help = true;
                    return cli;
                }
                "--config" | "-c" if i + 1 < args.len() => {
                    cli.config_path = Some(args[i + 1].clone());
                    i += 2;
                }
                "--host" if i + 1 < args.len() => {
                    cli.host = Some(args[i + 1].clone());
                    i += 2;
                }
                "--port" | "-p" if i + 1 < args.len() => {
                    cli.port = args[i + 1].parse().ok();
                    i += 2;
                }
                "--auth" if i + 1 < args.len() => {
                    cli.auth_enabled = args[i + 1].parse().ok();
                    i += 2;
                }
                "--no-auth" => {
                    cli.auth_enabled = Some(false);
                    cli.auth_mode = Some(AuthMode::None);
                    i += 1;
                }
                "--auth-mode" if i + 1 < args.len() => {
                    match args[i + 1].to_lowercase().as_str() {
                        "secret" => cli.auth_mode = Some(AuthMode::Secret),
                        "jwks" => cli.auth_mode = Some(AuthMode::Jwks),
                        "none" => cli.auth_mode = Some(AuthMode::None),
                        _ => {}
                    }
                    i += 2;
                }
                "--env-file" if i + 1 < args.len() => {
                    cli.env_file = Some(args[i + 1].clone());
                    i += 2;
                }
                "--jwks" | "--jwks-endpoint" if i + 1 < args.len() => {
                    cli.jwks_endpoint = Some(args[i + 1].clone());
                    i += 2;
                }
                "--logout-path" if i + 1 < args.len() => {
                    cli.logout_path = Some(args[i + 1].clone());
                    i += 2;
                }
                "--redis" | "--redis-url" if i + 1 < args.len() => {
                    cli.redis_url = Some(args[i + 1].clone());
                    i += 2;
                }
                "--rate-limit" if i + 1 < args.len() => {
                    cli.rate_limit_enabled = args[i + 1].parse().ok();
                    i += 2;
                }
                "--rate-limit-script" if i + 1 < args.len() => {
                    cli.rate_limit_script = Some(args[i + 1].clone());
                    i += 2;
                }
                _ => i += 1,
            }
        }

        cli
    }

    pub fn env_file_path(&self) -> Option<String> {
        self.env_file_path_with(|name| std::env::var(name).ok())
    }

    pub fn env_file_path_with(&self, lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
        self.env_file
            .clone()
            .or_else(|| lookup("BLUENO_ENV_FILE"))
            .filter(|path| !path.is_empty())
    }

    pub fn load_config(self) -> Result<GatewayConfig, ConfigError> {
        let path =
            GatewayConfig::resolve_path(self.config_path.as_deref(), |key| std::env::var(key).ok());
        let mut config = GatewayConfig::load(&path)?;

        if let Some(host) = self.host {
            config.server.host = host;
        }
        if let Some(port) = self.port {
            config.server.port = port;
        }
        if let Some(enabled) = self.auth_enabled {
            config.auth.enabled = enabled;
        }
        if let Some(mode) = self.auth_mode {
            config.auth.mode = mode;
        }
        if let Some(jwks_endpoint) = self.jwks_endpoint {
            config.auth.jwks_endpoint = jwks_endpoint;
        }
        if let Some(logout_path) = self.logout_path {
            config.auth.logout_path = logout_path;
        }
        if let Some(redis_url) = self.redis_url {
            config.redis.url = redis_url;
        }
        if let Some(enabled) = self.rate_limit_enabled {
            config.rate_limiter.enabled = enabled;
        }
        if let Some(script_path) = self.rate_limit_script {
            config.rate_limiter.script_path = Some(script_path.into());
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        std::iter::once("blueno")
            .chain(list.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn parses_env_file_flag() {
        let cli = Cli::parse_from(&args(&["--env-file", ".env"]));
        assert_eq!(cli.env_file.as_deref(), Some(".env"));
    }

    #[test]
    fn env_file_flag_wins_over_environment_variable() {
        let cli = Cli::parse_from(&args(&["--env-file", "flag.env"]));
        let path = cli.env_file_path_with(|_| Some("var.env".to_string()));
        assert_eq!(path.as_deref(), Some("flag.env"));
    }

    #[test]
    fn env_file_falls_back_to_environment_variable() {
        let cli = Cli::parse_from(&args(&[]));
        let path = cli
            .env_file_path_with(|name| (name == "BLUENO_ENV_FILE").then(|| "var.env".to_string()));
        assert_eq!(path.as_deref(), Some("var.env"));
        assert_eq!(cli.env_file_path_with(|_| None), None);
    }

    #[test]
    fn secret_flags_are_no_longer_recognized() {
        let cli = Cli::parse_from(&args(&[
            "--secret",
            "abc",
            "--jwt-secret",
            "def",
            "-p",
            "9000",
        ]));
        assert_eq!(cli.port, Some(9000));
        assert_eq!(cli.env_file, None);
        assert!(!cli.help);
    }
}
