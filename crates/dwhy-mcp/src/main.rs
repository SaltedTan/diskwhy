//! `dwhy-mcp`: the diskwhy MCP server, over stdio.
//!
//! stdout carries the protocol (JSON-RPC, one message per line); warnings
//! and errors go to stderr.

use std::io::Write;
use std::process::ExitCode;

use clap::Parser;
use dwhy_mcp::{MaxTier, Options, Server};
use rmcp::ServiceExt;

#[derive(Parser, Debug)]
#[command(
    name = "dwhy-mcp",
    version,
    about = "diskwhy MCP server (stdio): scan, explain, diff, watch, plan and apply for agent clients",
    after_help = "\
The model cannot raise what apply may remove: it takes no tier and no confirmations, so review
items are never removed through MCP. /etc/diskwhy/policy.toml and ~/.config/diskwhy/policy.toml
can lower --max-tier further. Every removal is recorded in the audit log (`dwhy audit`)."
)]
struct Cli {
    /// Highest tier `apply` removes. Review items need a person and are never removed here.
    #[arg(long, value_enum, default_value = "regenerable")]
    max_tier: MaxTier,
    /// No `apply` tool: scan, explain, diff, watch and plan only.
    #[arg(long)]
    read_only: bool,
    /// Worker threads for walks [default: one per CPU].
    #[arg(long, default_value_t = 0)]
    threads: usize,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // --help and --version print what was asked; usage errors exit
            // 1, as `dwhy`'s do.
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { 1 } else { 0 });
        }
    };
    let server = Server::new(Options {
        max_tier: cli.max_tier,
        read_only: cli.read_only,
        threads: cli.threads,
    });
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => return fail(&format!("cannot start the runtime: {e}")),
    };
    runtime.block_on(async move {
        let running = match server.serve(rmcp::transport::stdio()).await {
            Ok(r) => r,
            Err(e) => return fail(&format!("cannot start the server: {e}")),
        };
        match running.waiting().await {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => fail(&e.to_string()),
        }
    })
}

fn fail(msg: &str) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "dwhy-mcp: error: {msg}");
    ExitCode::from(1)
}
