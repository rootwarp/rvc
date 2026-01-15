use clap::Parser;

#[derive(Parser)]
#[command(name = "rvc")]
#[command(about = "Rust Validator Client", long_about = None)]
struct Cli {}

fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();

    tracing_subscriber::fmt::init();
    tracing::info!("rvc starting...");

    Ok(())
}
