// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]

// Import the macro. Don't forget to add `error-chain` in your
// `Cargo.toml`!
// #[macro_use]
extern crate error_chain;
mod errors ;
//use crate::errors::{ErrorKind, Result};


use crate::errors::{Result};
use std::env;
use eosio_api::json_rpc::EOSRPC;

fn run() -> Result<bool> {
//    use std::fs::File;
    let args: Vec<String> = env::args().collect();
    let host = {
        if args.len() >1 {
            &args[1]
        } else {
            "https://api.testnet.eos.io"
        }
    };
    let eos = EOSRPC::blocking(String::from(host));
    let gi = eos.get_info()?;
    eprintln!("{:#?}",gi);

    Ok(true)
}

fn main() {
    eprintln!("This is non-operational. need eosio-api to be semi-operational first");
    if let Err(ref e) = run() {
        println!("error: {}", e);

        for e in e.iter().skip(1) {
            println!("caused by: {}", e);
        }

        // The backtrace is not always generated. Try to run this example
        // with `RUST_BACKTRACE=1`.
        if let Some(backtrace) = e.backtrace() {
            println!("backtrace: {:?}", backtrace);
        }

        ::std::process::exit(1);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    #[ignore]
    fn dummy() -> Result<()> {
        Ok(())
    }
}
