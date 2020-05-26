use crate::errors::{Result, ErrorKind};
use std::fs;
use eosio_client_keys::hash::hash_sha256;

const WASM_COOKIE: [u8;8] = [0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00];

pub struct WASM {
    pub code:Vec<u8>
}
impl WASM {
    const HEXMAP: [char;16]= ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',  'a', 'b', 'c', 'd', 'e', 'f'];
    pub fn _read_hex_string(_in_str: String) -> Result<WASM> {
        Err("TBD".into())
    }
    pub fn read_file(filename: &str) -> Result<WASM> {
        let file = fs::read(filename)?;
        let slice = &file[0..WASM_COOKIE.len()].to_vec();
        let matching = slice.iter().zip(WASM_COOKIE.iter()).filter(|&(a, b)| a == b).count();

        if matching == WASM_COOKIE.len() {
            Ok(WASM{  code: file })
        } else {
            Err(ErrorKind::InvalidWASMFormat.into())
        }
    }
    pub fn hash(&self) -> Vec<u8> {
        hash_sha256(&self.code)
    }
    pub fn to_hex(&self) -> String {
        let mut s:String = String::new();
        for byt in &self.code {
            s.push( WASM::HEXMAP[(byt >> 4) as usize] );
            s.push( WASM::HEXMAP[(byt & 0xf) as usize]);
        }
        s
    }
    pub fn dummy() -> Vec<u8> {
       //WASM_COOKIE.to_vec()
        Vec::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn read_wasm() -> Result<()> {
         WASM::read_file("test/good.wasm")?;
        Ok(())
    }
}
