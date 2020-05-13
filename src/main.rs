// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]

// Import the macro. Don't forget to add `error-chain` in your
// `Cargo.toml`!
#[macro_use]
extern crate error_chain;
mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {}
}
//use crate::errors::{ErrorKind, Result};

use errors::*;

fn run() -> Result<bool> {
    use std::fs::File;

    // This operation will fail
    File::open("contacts")
        .chain_err(|| "unable to open contacts file")?;

    Ok(true)
}

fn main() {
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
