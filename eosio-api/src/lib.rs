// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]
//

extern crate reqwest;
extern crate serde_json;
#[macro_use] extern crate error_chain;
#[macro_use] extern crate lazy_static;
extern crate base64;
extern crate bs58;
extern crate ripemd160;
extern crate eosio_keys;
mod numeric;
mod api_types;
mod json_rpc;
mod wasm;
mod abi;
mod wallet_types;
mod errors;


pub fn hello() {
    println!("hello");
}

#[cfg(test)]
mod tests {
    // TBD
}
