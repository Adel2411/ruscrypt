use anyhow::Result;
use colored::*;
use std::env;

mod asym;
mod block;
mod classical;
mod cli;
mod dispatcher;
mod hash;
mod interactive;
mod stream;
mod utils;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let should_print_banner = args.len() == 1
        || args.iter().any(|arg: &String| {
            arg == "--help" || arg == "-h" || arg == "--version" || arg == "-V"
        });

    if should_print_banner {
        print_banner();
    }

    let parsed_args = cli::parse_args();
    dispatcher::dispatch_command(parsed_args)?;

    Ok(())
}

fn print_banner() {
    println!(
        "{}",
        r"
  _____             _____                  _   
 |  __ \           / ____|                | |  
 | |__) |   _ ___ | |     _ __ _   _ _ __ | |_ 
 |  _  / | | / __|| |    | '__| | | | '_ \| __|
 | | \ \ |_| \__ \| |____| |  | |_| | |_) \ |_ 
 |_|  \_\__,_|___/ \_____|_|   \__, | .__/ \__|
                                __/ | |            
                               |___/|_|            
    "
        .yellow()
    );

    println!("{}", "⚡ Lightning-fast cryptography toolkit ⚡".yellow());
    println!();
}

