// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]
//

extern crate reqwest;
extern crate serde_json;
//#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;

extern crate base64;
extern crate bs58;
extern crate eosio_client_keys;
extern crate ripemd160;
pub mod abi;
pub mod api_types;
pub mod json_rpc;
mod numeric;
pub mod wasm;
//mod serialize;
pub mod errors;
pub mod wallet_types;

#[cfg(test)]
mod tests {
    // TBD
}
