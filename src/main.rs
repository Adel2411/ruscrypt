use anyhow::Result;
use colored::*;

mod cli;
mod dispatcher;
mod interactive;
mod utils;
mod classical;
mod hash;
mod stream;
mod block;
mod asym;

fn main() -> Result<()> {
    print_banner();
    
    let args = cli::parse_args();
    dispatcher::dispatch_command(args)?;
    
    Ok(())
}

fn print_banner() {
    println!("{}", r"
  _____             _____                  _   
 |  __ \           / ____|                | |  
 | |__) |   _ ___ | |     _ __ _   _ _ __ | |_ 
 |  _  / | | / __|| |    | '__| | | | '_ \| __|
 | | \ \ |_| \__ \| |____| |  | |_| | |_) \ |_ 
 |_|  \_\__,_|___/ \_____|_|   \__, | .__/ \__|
                                __/ | |            
                               |___/|_|            
    ".yellow());
    
    println!("{}", "⚡ Lightning-fast cryptography toolkit ⚡".yellow());
}