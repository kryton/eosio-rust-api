#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

//use std::ptr::null;
use rust_embed::RustEmbed;
use std::ffi::{CStr, CString};

/// embed main ABI files into client.
#[derive(RustEmbed)]
#[folder = "resources/"]
pub struct AbiFiles;

include!("./bindings.rs");
pub mod errors;

//#[macro_use]
extern crate error_chain;

use crate::errors::{Error, ErrorKind, Result};
use std::os::raw::c_char;

pub type ABIName = u64;

pub struct ABIEOS {
    context: *mut abieos_context,
}

impl ABIEOS {
    ///
    /// # Safety
    /// make sure you call destroy  after use
    pub fn new() -> ABIEOS {
        unsafe {
            let context: *mut abieos_context = abieos_create();
            ABIEOS { context }
        }
    }

    /// # Safety
    ///
    /// make sure you call destroy  after use
    pub fn new_with_abi(contract_name: &str, abi: &str) -> Result<ABIEOS> {
        unsafe {
            let context: *mut abieos_context = abieos_create();
            let abi_obj = ABIEOS { context };
            abi_obj.set_abi(contract_name, abi).map_err(|e| {
                abi_obj.destroy();
                Error::with_chain(e, "new_with_abi")
            })?;

            Ok(abi_obj)
        }
    }

    /// # Safety
    ///
    /// after destroy, don't use any other function
    pub fn destroy(&self) {
        unsafe {
            abieos_destroy(self.context);
        }
        //  self.context = null();
    }

    pub fn set_abi(&self, contract_name: &str, abi: &str) -> Result<bool> {
        let name = self.str_to_name(contract_name)?;
        let abi_cs = CString::new(abi)?;
        let result = unsafe { abieos_set_abi(self.context, name, abi_cs.as_ptr() as *const i8) };
        if result == 0 {
            self.abieos_error()?;
        }

        Ok(true)
    }

    pub fn str_to_name(&self, str_name: &str) -> Result<ABIName> {
        let cs = CString::new(str_name)?;
        let result = unsafe { abieos_string_to_name(self.context, cs.as_ptr() as *const i8) };
        Ok(result)
    }

    pub fn hex_to_json(&self, contract_name: &str, type_str: &str, hex: &[u8]) -> Result<String> {
        let name = self.str_to_name(contract_name)?;
        let typeCS = CString::new(type_str).unwrap();
        let hexCS = CString::new(hex).unwrap();
        let json_p = unsafe {
            abieos_hex_to_json(
                self.context,
                name,
                typeCS.as_ptr(),
                hexCS.as_ptr() as *const i8,
            )
        };

        if json_p.is_null() {
            self.abieos_error()?;
            Err("FAIL".into()) // not reached
        } else {
            let json = unsafe { ABIEOS::fix_json(CStr::from_ptr(json_p).to_str()?)? };
            Ok(json)
        }
    }

    pub fn bin_to_json(&self, contract_name: &str, type_str: &str, hex: &[u8]) -> Result<String> {
        let name = self.str_to_name(contract_name)?;
        let typeCS = CString::new(type_str).unwrap();
        // let hexCS = CString::new(hex).unwrap();
        let json_p = unsafe {
            abieos_bin_to_json(
                self.context,
                name,
                typeCS.as_ptr(),
                hex.as_ptr() as *const i8,
                hex.len() as u64,
            )
        };

        if json_p.is_null() {
            self.abieos_error()?;
            Err("FAIL".into()) // not reached
        } else {
            unsafe {
                let json = ABIEOS::fix_json(CStr::from_ptr(json_p).to_str()?)?;
                Ok(json.clone())
            }
        }
    }
    fn json_to_xx(&self, contract_name: &str, type_str: &str, json: &str) -> Result<i32> {
        let name = self.str_to_name(contract_name)?;
        let typeCS = CString::new(type_str).unwrap();
        let jsonCS = CString::new(json).unwrap();
        let result = unsafe {
            abieos_json_to_bin_reorderable(
                self.context,
                name,
                typeCS.as_ptr(),
                jsonCS.as_ptr() as *const i8,
            )
        };
        Ok(result)
    }
    ///
    /// Safety
    ///
    /// abieos_get_xxx calls can potentially overwrite the memory returned on the next call.
    pub fn json_to_hex(&self, contract_name: &str, type_str: &str, json: &str) -> Result<String> {
        match self.json_to_xx(contract_name, type_str, json) {
            Ok(0) => {
                self.abieos_error()
                    .map_err(|e| Error::with_chain(e, "json_to_hex"))?;
                Err("FAIL".into()) // not reached
            }
            Ok(_) => {
                unsafe {
                    let hex_p = abieos_get_bin_hex(self.context);
                    let s = CStr::from_ptr(hex_p);
                    // this should copy the memory over
                    Ok(String::from(s.to_str()?).clone())
                }
            }
            Err(e) => Err(Error::with_chain(e, "json_to_hex")),
        }
    }

    ///
    /// Safety
    ///
    /// abieos_get_xxx calls can potentially overwrite the memory returned on the next call.
    pub fn json_to_bin(&self, contract_name: &str, type_str: &str, json: &str) -> Result<Vec<u8>> {
        match self.json_to_xx(contract_name, type_str, json) {
            Ok(0) => {
                self.abieos_error()?;
                Err("FAIL".into()) // not reached
            }
            Ok(_) => unsafe {
                let bin_size: usize = abieos_get_bin_size(self.context) as usize;
                let bin: *const ::std::os::raw::c_char = abieos_get_bin_data(self.context);

                let v: &[u8] = std::slice::from_raw_parts(bin as *const u8, bin_size);
                let ve: Vec<u8> = v.to_vec().clone();
                Ok(ve)
            },
            Err(e) => Err(Error::with_chain(e, "json_to_hex")),
        }
    }

    fn abieos_error(&self) -> Result<String> {
        unsafe {
            let err_raw: *const c_char = abieos_get_error(self.context);
            if !err_raw.is_null() {
                let err_s = CStr::from_ptr(err_raw).to_str()?;
                Err(ErrorKind::ABIEOS(String::from(err_s)).into())
            } else {
                Err(ErrorKind::ABIEOS_INT.into())
            }
        }
    }

    // for some reason json returned has a 0x10 instead of a newline.
    // before removing this. make sure you copy the output of the API call to rust-managed memory
    //
    fn fix_json(in_str: &str) -> Result<String> {
        let mut x: String;
        let mut i = 0;
        x = in_str.replacen("\\u000A", "\\n", 999);
        while x.contains("\\u000A") {
            x = x.replacen("\\u000A", "\\n", 999);
            i += 1;
            if i > 100 {
                return Err(ErrorKind::ABIEOS_LOOP.into());
            }
        }
        Ok(x)
    }
}
fn hex_to_bin_char(c: u8) -> u8 {
    if c >= b'a' && c <= b'z' {
        let v: u8 = (c - b'a') + 10;
        return v;
    }
    if c >= b'0' && c <= b'9' {
        let v = c - b'0';
        return v;
    }
    0
}

pub fn hex_to_bin(hex: &str) -> Vec<u8> {
    let mut bin: Vec<u8> = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = hex_to_bin_char(bytes[i]).checked_shl(4).unwrap() + hex_to_bin_char(bytes[i + 1]);
        i += 2;
        bin.push(b);
    }
    bin
}
pub fn varuint32_from_bin(bin_str: &[u8]) -> Result<(u32, Vec<u8>)> {
    let mut dest: u32 = 0;
    let mut shift = 0;
    let mut i = 0;
    let mut b: u8;
    while {
        if shift >= 35 {
            return Err(ErrorKind::ABIEOS_VARUINT_ENCODING.into());
        }
        b = bin_str[i];
        dest |= ((b & 0x7f) as u32).checked_shl(shift).unwrap();
        shift += 7;
        i += 1;
        i < bin_str.len() && b & 0x80 != 0
    } {}

    Ok((dest, bin_str[i..].to_vec()))
}
pub fn varuint64_from_bin(bin_str: &[u8]) -> Result<(u64, Vec<u8>)> {
    let mut dest: u64 = 0;
    let mut shift = 0;
    let mut i = 0;
    let mut b: u8;
    while {
        if shift >= 70 {
            return Err(ErrorKind::ABIEOS_VARUINT_ENCODING.into());
        }
        b = bin_str[i];
        dest |= ((b & 0x7f) as u64).checked_shl(shift).unwrap();
        shift += 7;
        i += 1;
        i < bin_str.len() && b & 0x80 != 0
    } {}
    Ok((dest, bin_str[i..].to_vec()))
}

pub mod eosio_datetime_format {
    use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    const FORMAT: &str = "%Y-%m-%dT%H:%M:%S";

    // The signature of a serialize_with function must follow the pattern:
    //
    //    fn serialize<S>(&T, S) -> Result<S::Ok, S::Error>
    //    where
    //        S: Serializer
    //
    // although it may also be generic over the input types T.
    #[allow(dead_code)]
    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", date.format(FORMAT));
        serializer.serialize_str(&s)
    }

    // The signature of a deserialize_with function must follow the pattern:
    //
    //    fn deserialize<'de, D>(D) -> Result<T, D::Error>
    //    where
    //        D: Deserializer<'de>
    //
    // although it may also be generic over the output types T.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        let len = s.len();
        let slice_len = if s.contains('.') {
            len.saturating_sub(4)
        } else {
            len
        };

        // match Utc.datetime_from_str(&s, FORMAT) {
        let sliced = &s[0..slice_len];
        match NaiveDateTime::parse_from_str(sliced, FORMAT) {
            Err(_e) => {
                eprintln!("DateTime Fail {} {:#?}", sliced, _e);
                Err(serde::de::Error::custom(_e))
            }
            Ok(dt) => Ok(Utc.from_utc_datetime(&dt)),
        }
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use std::fs;

    const JSON: &str = "{ \
  \"expiration\": \"2018-08-02T20:24:36\", \
  \"ref_block_num\": 14207, \
  \"ref_block_prefix\": 1438248607, \
  \"max_net_usage_words\": 0, \
  \"max_cpu_usage_ms\": 0, \
  \"delay_sec\": 0, \
  \"context_free_actions\": [], \
  \"actions\": [{ \
      \"account\": \"eosio\", \
      \"name\": \"newaccount\", \
      \"authorization\": [{ \
          \"actor\": \"eosio\", \
          \"permission\": \"active\"  }], \
      \"data\": \"0000000000ea305500a6823403ea30550100000001000240cc0bf90a5656c8bb81f0eb86f49f89613c5cd988c018715d4646c6bd0ad3d8010000000100000001000240cc0bf90a5656c8bb81f0eb86f49f89613c5cd988c018715d4646c6bd0ad3d801000000\" \
    }], \
  \"transaction_extensions\": []}";

    const PACKED: &str = "8468635b7f379feeb95500000000010000000000ea305500409e9a2264b89a010000000000ea305500000000a8ed3232660000000000ea305500a6823403ea30550100000001000240cc0bf90a5656c8bb81f0eb86f49f89613c5cd988c018715d4646c6bd0ad3d8010000000100000001000240cc0bf90a5656c8bb81f0eb86f49f89613c5cd988c018715d4646c6bd0ad3d80100000000";

    #[test]
    fn tst_abi() -> Result<()> {
        let hex = "0e656f73696f3a3a6162692f312e30010c6163636f756e745f6e616d65046e616d6505087472616e7366657200040466726f6d0c6163636f756e745f6e616d6502746f0c6163636f756e745f6e616d65087175616e74697479056173736574046d656d6f06737472696e67066372656174650002066973737565720c6163636f756e745f6e616d650e6d6178696d756d5f737570706c79056173736574056973737565000302746f0c6163636f756e745f6e616d65087175616e74697479056173736574046d656d6f06737472696e67076163636f756e7400010762616c616e63650561737365740e63757272656e63795f7374617473000306737570706c790561737365740a6d61785f737570706c79056173736574066973737565720c6163636f756e745f6e616d6503000000572d3ccdcd087472616e73666572bc072d2d2d0a7469746c653a20546f6b656e205472616e736665720a73756d6d6172793a205472616e7366657220746f6b656e732066726f6d206f6e65206163636f756e7420746f20616e6f746865722e0a69636f6e3a2068747470733a2f2f63646e2e746573746e65742e6465762e62316f70732e6e65742f746f6b656e2d7472616e736665722e706e6723636535316566396639656563613334333465383535303765306564343965373666666631323635343232626465643032353566333139366561353963386230630a2d2d2d0a0a2323205472616e73666572205465726d73202620436f6e646974696f6e730a0a492c207b7b66726f6d7d7d2c20636572746966792074686520666f6c6c6f77696e6720746f206265207472756520746f207468652062657374206f66206d79206b6e6f776c656467653a0a0a312e204920636572746966792074686174207b7b7175616e746974797d7d206973206e6f74207468652070726f6365656473206f66206672617564756c656e74206f722076696f6c656e7420616374697669746965732e0a322e2049206365727469667920746861742c20746f207468652062657374206f66206d79206b6e6f776c656467652c207b7b746f7d7d206973206e6f7420737570706f7274696e6720696e6974696174696f6e206f662076696f6c656e636520616761696e7374206f74686572732e0a332e2049206861766520646973636c6f73656420616e7920636f6e747261637475616c207465726d73202620636f6e646974696f6e732077697468207265737065637420746f207b7b7175616e746974797d7d20746f207b7b746f7d7d2e0a0a4920756e6465727374616e6420746861742066756e6473207472616e736665727320617265206e6f742072657665727369626c6520616674657220746865207b7b247472616e73616374696f6e2e64656c61795f7365637d7d207365636f6e6473206f72206f746865722064656c617920617320636f6e66696775726564206279207b7b66726f6d7d7d2773207065726d697373696f6e732e0a0a4966207468697320616374696f6e206661696c7320746f20626520697272657665727369626c7920636f6e6669726d656420616674657220726563656976696e6720676f6f6473206f722073657276696365732066726f6d20277b7b746f7d7d272c204920616772656520746f206569746865722072657475726e2074686520676f6f6473206f72207365727669636573206f7220726573656e64207b7b7175616e746974797d7d20696e20612074696d656c79206d616e6e65722e0000000000a531760569737375650000000000a86cd445066372656174650002000000384f4d113203693634010863757272656e6379010675696e743634076163636f756e740000000000904dc603693634010863757272656e6379010675696e7436340e63757272656e63795f737461747300000000";
        let jsonResult = "{\"version\":\"eosio::abi/1.0\",\"types\":[{\"new_type_name\":\"account_name\",\"type\":\"name\"}],\"structs\":[{\"name\":\"transfer\",\"base\":\"\",\"fields\":[{\"name\":\"from\",\"type\":\"account_name\"},{\"name\":\"to\",\"type\":\"account_name\"},{\"name\":\"quantity\",\"type\":\"asset\"},{\"name\":\"memo\",\"type\":\"string\"}]},{\"name\":\"create\",\"base\":\"\",\"fields\":[{\"name\":\"issuer\",\"type\":\"account_name\"},{\"name\":\"maximum_supply\",\"type\":\"asset\"}]},{\"name\":\"issue\",\"base\":\"\",\"fields\":[{\"name\":\"to\",\"type\":\"account_name\"},{\"name\":\"quantity\",\"type\":\"asset\"},{\"name\":\"memo\",\"type\":\"string\"}]},{\"name\":\"account\",\"base\":\"\",\"fields\":[{\"name\":\"balance\",\"type\":\"asset\"}]},{\"name\":\"currency_stats\",\"base\":\"\",\"fields\":[{\"name\":\"supply\",\"type\":\"asset\"},{\"name\":\"max_supply\",\"type\":\"asset\"},{\"name\":\"issuer\",\"type\":\"account_name\"}]}],\"actions\":[{\"name\":\"transfer\",\"type\":\"transfer\",\"ricardian_contract\":\"---\\ntitle: Token Transfer\\nsummary: Transfer tokens from one account to another.\\nicon: https://cdn.testnet.dev.b1ops.net/token-transfer.png#ce51ef9f9eeca3434e85507e0ed49e76fff1265422bded0255f3196ea59c8b0c\\n---\\n\\n## Transfer Terms & Conditions\\n\\nI, {{from}}, certify the following to be true to the best of my knowledge:\\n\\n1. I certify that {{quantity}} is not the proceeds of fraudulent or violent activities.\\n2. I certify that, to the best of my knowledge, {{to}} is not supporting initiation of violence against others.\\n3. I have disclosed any contractual terms & conditions with respect to {{quantity}} to {{to}}.\\n\\nI understand that funds transfers are not reversible after the {{$transaction.delay_sec}} seconds or other delay as configured by {{from}}'s permissions.\\n\\nIf this action fails to be irreversibly confirmed after receiving goods or services from '{{to}}', I agree to either return the goods or services or resend {{quantity}} in a timely manner.\"},{\"name\":\"issue\",\"type\":\"issue\",\"ricardian_contract\":\"\"},{\"name\":\"create\",\"type\":\"create\",\"ricardian_contract\":\"\"}],\"tables\":[{\"name\":\"accounts\",\"index_type\":\"i64\",\"key_names\":[\"currency\"],\"key_types\":[\"uint64\"],\"type\":\"account\"},{\"name\":\"stat\",\"index_type\":\"i64\",\"key_names\":[\"currency\"],\"key_types\":[\"uint64\"],\"type\":\"currency_stats\"}],\"ricardian_clauses\":[],\"error_messages\":[],\"abi_extensions\":[],\"variants\":[]}";
        let abi = fs::read_to_string("abi.abi.json").unwrap();

        let abieos: ABIEOS = ABIEOS::new_with_abi("eosio", &abi)?;
        let do_hex_2_json = || -> Result<String> {
            let json = abieos.hex_to_json("eosio", "abi_def", hex.as_bytes())?;
            assert_eq!(jsonResult, json);
            Ok(String::from(json))
        }();
        let do_json_2_hex = || -> Result<String> {
            let hex_out = abieos.json_to_hex("eosio", "abi_def", jsonResult)?;
            assert_eq!(hex_out.to_ascii_lowercase(), hex);
            Ok(hex_out)
        }();
        abieos.destroy();
        do_hex_2_json?;
        do_json_2_hex?;

        Ok(())
    }

    #[test]
    fn tst_txn() -> Result<()> {
        let hex = "AE0D635CDCAC90A6DCFA000000000100A6823403EA3055000000572D3CCDCD0100AEAA4AC15CFD4500000000A8ED32323B00AEAA4AC15CFD4500000060D234CD3DA06806000000000004454F53000000001A746865206772617373686F70706572206C69657320686561767900";
        let jsonResult = "{\"expiration\":\"2019-02-12T18:17:18.000\",\"ref_block_num\":44252,\"ref_block_prefix\":4208764560,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"cryptkeeper\",\"permission\":\"active\"}],\"data\":\"00AEAA4AC15CFD4500000060D234CD3DA06806000000000004454F53000000001A746865206772617373686F70706572206C696573206865617679\"}],\"transaction_extensions\":[]}";
        let abi = fs::read_to_string("transaction.abi.json").unwrap();

        let abieos: ABIEOS = ABIEOS::new_with_abi("eosio", &abi)?;
        let do_hex_2_json = || -> Result<String> {
            let json = abieos.hex_to_json("eosio", "transaction", hex.as_bytes())?;
            assert_eq!(jsonResult, json);
            Ok(String::from(json))
        }();
        let do_json_2_hex = || -> Result<String> {
            let hex_out = abieos.json_to_hex("eosio", "transaction", jsonResult)?;
            assert_eq!(hex_out.to_ascii_uppercase(), hex);

            Ok(hex_out)
        }();
        abieos.destroy();
        do_json_2_hex?;
        do_hex_2_json?;

        Ok(())
    }

    #[test]
    pub fn test_from_example_2h() -> Result<()> {
        let abi = fs::read_to_string("transaction.abi.json").unwrap();

        let abieos: ABIEOS = ABIEOS::new_with_abi("eosio", &abi)?;

        let do_json_2_hex = || -> Result<String> {
            let hex_out = abieos.json_to_hex("eosio", "transaction", JSON)?;
            assert_eq!(hex_out.to_ascii_lowercase(), PACKED);
            Ok(hex_out)
        }();
        abieos.destroy();
        do_json_2_hex?;

        Ok(())
    }

    #[test]
    pub fn test_ttt_abi() -> Result<()> {
        let test_abi = fs::read_to_string("test/good-2.abi").unwrap();
        let abi = fs::read_to_string("abi.abi.json").unwrap();

        let abieos: ABIEOS = ABIEOS::new_with_abi("eosio", &abi)?;
        let hex_out = abieos.json_to_hex("eosio", "abi_def", &test_abi);
        abieos.destroy();
        hex_out?;

        Ok(())
    }

    #[test]
    pub fn test_ttt_abi_bin() -> Result<()> {
        let test_abi = fs::read_to_string("test/good-2.abi").unwrap();
        let abi = fs::read_to_string("abi.abi.json").unwrap();

        let abieos: ABIEOS = ABIEOS::new_with_abi("eosio", &abi)?;
        let hex_out = abieos.json_to_hex("eosio", "abi_def", &test_abi);
        let bin_out = abieos.json_to_bin("eosio", "abi_def", &test_abi);
        abieos.destroy();
        let hex = hex_out?.to_string();
        let bin = bin_out?;
        let mut bin_h: String = String::with_capacity(bin.len() * 2);
        for u in &bin {
            let hex_bit = char_to_hex(u)?.into_bytes();
            bin_h.push(char::from(hex_bit[0]));
            bin_h.push(char::from(hex_bit[1]));
        }
        assert_eq!(hex.to_ascii_lowercase(), bin_h.to_ascii_lowercase());
        let abieos: ABIEOS = ABIEOS::new_with_abi("eosio", &abi)?;
        let _json_out = abieos.bin_to_json("eosio", "abi_def", &bin).map_err(|e| {
            abieos.destroy();
            Error::with_chain(e, "parsing shipper abi")
        })?;
        //assert_eq!(test_abi,json_out);

        Ok(())
    }

    #[test]
    pub fn test_from_example_2j() -> Result<()> {
        let abi = fs::read_to_string("transaction.abi.json").unwrap();

        let abieos: ABIEOS = ABIEOS::new_with_abi("eosio", &abi)?;
        let _do_hex_2_json = || -> Result<String> {
            let json = abieos.hex_to_json("eosio", "transaction", PACKED.as_bytes())?;
            let hex_out = abieos.json_to_hex("eosio", "transaction", &json)?;
            assert_eq!(hex_out.to_ascii_lowercase(), PACKED);
            Ok(json)
        }();
        abieos.destroy();

        Ok(())
    }
    #[test]
    fn test_varuint32() -> Result<()> {
        let hex_str = "b6843d0123";
        let hex_str2 = "01002BAD64FF47";
        let hex_str3 = "ffffffff0faa";
        let hex_str4 = "ffffffffff0faa";
        let bin_str = hex_to_bin(&hex_str);
        let (val, bin_str_ex) = varuint32_from_bin(&bin_str)?;
        assert_eq!(999990, val);
        assert_eq!(bin_str_ex.len(), 2);
        assert_eq!(bin_str_ex[0], 01);
        assert_eq!(bin_str_ex[1], 0x23);
        let bin_str2 = hex_to_bin(&hex_str2);
        let (val, bin_str_ex) = varuint32_from_bin(&bin_str2)?;
        assert_eq!(1, val);
        assert_eq!(bin_str_ex.len(), 6);
        let (val64, bin_str_ex) = varuint64_from_bin(&bin_str)?;
        assert_eq!(999990, val64);
        assert_eq!(bin_str_ex.len(), 2);
        assert_eq!(bin_str_ex[0], 01);
        let bin_str3 = hex_to_bin(&hex_str3);
        let (val, _bin_str_ex) = varuint32_from_bin(&bin_str3)?;
        assert_eq!(0xff_ff_ff_ff, val);
        let bin_str4 = hex_to_bin(&hex_str4);
        let v: Result<(u32, Vec<u8>)> = varuint32_from_bin(&bin_str4);
        assert!(v.is_err());
        let v: Result<(u64, Vec<u8>)> = varuint64_from_bin(&bin_str4);
        assert!(v.is_ok());
        assert_eq!(0x7f_ff_ff_ff_ff, v?.0);

        Ok(())
    }

    fn char_to_hex(c: &u8) -> Result<String> {
        let mut r: [u8; 2] = [0; 2];
        let b1_1 = c & 0xf0;
        let b1 = b1_1.checked_shr(4).unwrap_or(0);
        if b1 >= 10 {
            r[0] = b1 - 10 + b'a';
        } else {
            r[0] = b1 + b'0';
        }
        let b1 = c & 0x0f;
        if b1 >= 10 {
            r[1] = b1 - 10 + b'a';
        } else {
            r[1] = b1 + b'0';
        }
        Ok(String::from_utf8(r.to_vec())?)
    }
}
