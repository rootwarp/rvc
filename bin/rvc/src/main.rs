use clap::{Parser, Subcommand};
use rvc::duty_tracker::DutyTrackerService;
use rvc::DutyTrackerServer;
use tonic::transport::Server;

const DEFAULT_GRPC_PORT: u16 = 8081;

#[derive(Parser)]
#[command(name = "rvc")]
#[command(about = "Rust Validator Client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the validator client
    Start {
        #[arg(long, default_value_t = DEFAULT_GRPC_PORT)]
        grpc_port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt::init();

    match cli.command {
        Commands::Start { grpc_port } => {
            start_server(grpc_port).await?;
        }
    }

    Ok(())
}

async fn start_server(grpc_port: u16) -> anyhow::Result<()> {
    tracing::info!("rvc starting...");

    let addr = format!("0.0.0.0:{}", grpc_port).parse()?;
    let duty_tracker = DutyTrackerService::new();

    tracing::info!("gRPC server listening on {}", addr);

    Server::builder().add_service(DutyTrackerServer::new(duty_tracker)).serve(addr).await?;

    Ok(())
}
