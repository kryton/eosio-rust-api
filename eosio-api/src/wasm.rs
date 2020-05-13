use crate::errors::{Result, ErrorKind};
use std::fs;
use eosio_keys::hash::hash_sha256;

const WASM_COOKIE: [u8;8] = [0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00];
const HASH_LEN:usize = 16;

pub struct WASM {
    hash:Vec<u8>,
    pub code:Vec<u8>
}
impl WASM {
    pub fn read_hex_string(in_str: String) -> Result<WASM> {
        Err("TBD".into())
    }
    pub fn read_file(filename: &str) -> Result<WASM> {
        let file = fs::read(filename)?;
        let slice = &file[0..WASM_COOKIE.len()].to_vec();
        let matching = slice.iter().zip(WASM_COOKIE.iter()).filter(|&(a, b)| a == b).count();

        if matching == WASM_COOKIE.len() {
            let hash = hash_sha256(&file);
            Ok(WASM{ hash, code: file })
        } else {
            Err(ErrorKind::InvalidWASMFormat.into())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn read_wasm() {
        match WASM::read_file("test/good.wasm") {
            Err(e) => {
                eprintln!("{:?}", e);
                assert!(false)
            },
            Ok(w) =>{},
        }
    }
}
