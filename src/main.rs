mod app;
mod cli;

use blueno::config;
use cli::Cli;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if cli.help {
        println!("{}", cli::HELP);
        return Ok(());
    }

    if let Some(path) = cli.env_file_path() {
        config::load_env_file(path)?;
    }

    let config = cli.load_config()?;
    app::run(config).await
}
