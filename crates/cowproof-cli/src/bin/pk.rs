#[tokio::main]
async fn main() -> std::process::ExitCode {
    cowproof_cli::pk::run(std::env::args_os().skip(1)).await
}
