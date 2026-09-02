use std::net::SocketAddr;

use clap::Parser;
use queue_overflow_proxy::run_until_ctrl_c;
use queue_overflow_proxy::ProxyConfig;

#[derive(Debug, Parser)]
#[command(about = "Inject deterministic QUEUE_OVERFLOW responses before proxying to Acki Nacki")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8099")]
    listen: SocketAddr,

    #[arg(long, default_value = "https://shellnet.ackinacki.org")]
    upstream: String,

    #[arg(long, default_value_t = 3)]
    fail_first: usize,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = Args::parse();
    run_until_ctrl_c(ProxyConfig {
        listen: args.listen,
        upstream: args.upstream,
        fail_first: args.fail_first,
    })
    .await
}
