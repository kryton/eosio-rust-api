#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ptr::null;
use std::ffi::{CStr, CString};

include!("./bindings.rs");
mod errors;

//#[macro_use]
extern crate error_chain;
//#[macro_use] extern crate lazy_static;

use crate::errors::{ErrorKind, Result};
use std::os::raw::c_char;



type ABIName = u64;

pub struct ABIEOS {
    context: *mut abieos_context
}

impl ABIEOS {
    ///
    /// # Safety
    /// make sure you destroy this after use
    pub unsafe fn new() -> ABIEOS {
        let context: *mut abieos_context = abieos_create();
        ABIEOS { context }
    }

    /// # Safety
    /// make sure you destroy this after use
    pub unsafe fn new_with_abi(contract_name: &str, abi: &str) -> Result<ABIEOS> {
        let context: *mut abieos_context = abieos_create();
        let abi_obj = ABIEOS { context };
        let result = abi_obj.set_abi(contract_name,abi);
        if result.is_err() {
            abi_obj.destroy();
            Err(result.unwrap_err())
        } else {
            Ok(abi_obj)
        }
    }
    /// # Safety
    /// after destroy, don't use any other function
    pub unsafe fn destroy(&self) {
        abieos_destroy(self.context);
        //  self.context = null();
    }

    /// # Safety
    /// make sure you destroy this after use
    pub unsafe fn set_abi(&self, contract_name: &str, abi: &str) -> Result<bool> {
        let name = self.str_to_name(contract_name)?;
        let abi_cs = CString::new(abi)?;
        let result = abieos_set_abi(self.context, name, abi_cs.as_ptr() as *const i8);
        if result == 0 {
            self.abieos_error()?;
        }
        Ok(true)
    }

    /// # Safety
    /// make sure you destroy this after use
    pub unsafe fn str_to_name(&self, str_name: &str) -> Result<ABIName> {
        let cs = CString::new(str_name)?;
        Ok(abieos_string_to_name(self.context, cs.as_ptr() as *const i8))
    }

    /// # Safety
    /// make sure you destroy this after use
    pub unsafe fn hex_to_json(&self, contract_name: &str, type_str: &str, hex: &str) -> Result<String> {
        let name = self.str_to_name(contract_name)?;
        let typeCS = CString::new(type_str).unwrap();
        let hexCS = CString::new(hex).unwrap();
        let json_p = abieos_hex_to_json(self.context, name, typeCS.as_ptr(), hexCS.as_ptr() as *const i8);
        if json_p == null() {
            self.abieos_error()?;
            Err("FAIL".into()) // not reached
        } else {
            let json = ABIEOS::fix_json(CStr::from_ptr(json_p).to_str()?)?;
            Ok(json)
        }
    }

    /// # Safety
    /// make sure you destroy this after use
    pub unsafe fn json_to_hex(&self, contract_name: &str, type_str: &str, json: &str) -> Result<&str> {
        let name = self.str_to_name(contract_name)?;
        let typeCS = CString::new(type_str).unwrap();
        let jsonCS = CString::new(json).unwrap();
        let result = abieos_json_to_bin(self.context, name, typeCS.as_ptr(), jsonCS.as_ptr() as *const i8);

        if result == 0 {
            self.abieos_error()?;
            Err("FAIL".into()) // not reached
        } else {
            let _bin_size = abieos_get_bin_size(self.context);
            let hex_p = abieos_get_bin_hex(self.context);
            let s = CStr::from_ptr(hex_p);

            Ok(s.to_str()?)
        }
    }

    /// # Safety
    /// make sure you destroy this after use
    unsafe fn abieos_error(&self) -> Result<String> {
        let err_raw: *const c_char = abieos_get_error(self.context);
        if err_raw != null() {
            let err_s = CStr::from_ptr(err_raw).to_str()?;
            Err(ErrorKind::ABIEOS(String::from(err_s)).into())
        } else {
            Err(ErrorKind::ABIEOS_INT.into())
        }
    }

    // for some reason json returned has a 0x10 instead of a newline.
     fn fix_json(in_str: &str) -> Result<String> {
        let mut x: String;
        let mut i = 0;
        x = in_str.replacen("\\u000A", "\\n", 999);
        while x.contains("\\u000A")
        {
            x = x.replacen("\\u000A", "\\n", 999);
            i += 1;
            if i > 100 {
                return Err(ErrorKind::ABIEOS_LOOP.into());
            }
        }
        Ok(x)
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
        unsafe {
            let abieos: ABIEOS = ABIEOS::new_with_abi("eosio",&abi)?;
            let do_hex_2_json = || -> Result<String> {
                let json = abieos.hex_to_json("eosio", "abi_def", hex)?;
                assert_eq!(jsonResult, json);
                Ok(String::from(json))

            }();
            let do_json_2_hex = || -> Result<&str> {
                let hex_out = abieos.json_to_hex("eosio", "abi_def", jsonResult)?;
                assert_eq!(hex_out.to_ascii_lowercase(), hex);
                Ok(hex_out)
            }();
            abieos.destroy();
            do_hex_2_json?;
            do_json_2_hex?;
        }
        Ok(())
    }
    #[test]
    fn tst_txn() -> Result<()> {
        let hex = "AE0D635CDCAC90A6DCFA000000000100A6823403EA3055000000572D3CCDCD0100AEAA4AC15CFD4500000000A8ED32323B00AEAA4AC15CFD4500000060D234CD3DA06806000000000004454F53000000001A746865206772617373686F70706572206C69657320686561767900";
        let jsonResult = "{\"expiration\":\"2019-02-12T18:17:18.000\",\"ref_block_num\":44252,\"ref_block_prefix\":4208764560,\"max_net_usage_words\":0,\"max_cpu_usage_ms\":0,\"delay_sec\":0,\"context_free_actions\":[],\"actions\":[{\"account\":\"eosio.token\",\"name\":\"transfer\",\"authorization\":[{\"actor\":\"cryptkeeper\",\"permission\":\"active\"}],\"data\":\"00AEAA4AC15CFD4500000060D234CD3DA06806000000000004454F53000000001A746865206772617373686F70706572206C696573206865617679\"}],\"transaction_extensions\":[]}";
        let abi = fs::read_to_string("transaction.abi.json").unwrap();
        unsafe {
            let abieos: ABIEOS = ABIEOS::new_with_abi("eosio",&abi)?;
            let do_hex_2_json = || -> Result<String> {
                let json = abieos.hex_to_json("eosio", "transaction", hex)?;
                assert_eq!(jsonResult, json);
                Ok(String::from(json))
            }();
            let do_json_2_hex = || -> Result<&str> {
                let hex_out = abieos.json_to_hex("eosio", "transaction", jsonResult)?;
                assert_eq!(hex_out.to_ascii_uppercase(), hex);

                Ok(hex_out)
            }();
            abieos.destroy();
             do_json_2_hex?;
            do_hex_2_json?;

        }

        Ok(())
    }

    #[test]
    pub fn test_from_example_2h() -> Result<()> {
        let abi = fs::read_to_string("transaction.abi.json").unwrap();
        unsafe {
            let abieos: ABIEOS = ABIEOS::new_with_abi("eosio",&abi)?;

            let do_json_2_hex = || -> Result<&str> {
               let hex_out = abieos.json_to_hex("eosio", "transaction", JSON)?;
                assert_eq!(hex_out.to_ascii_lowercase(), PACKED);
                Ok(hex_out)
            }();
            abieos.destroy();
            do_json_2_hex?;
        }
        Ok(())
    }

    #[test]
    pub fn test_from_example_2j() -> Result<()> {
        let abi = fs::read_to_string("transaction.abi.json").unwrap();
        unsafe {
            let abieos: ABIEOS = ABIEOS::new_with_abi("eosio",&abi)?;
            let _do_hex_2_json = || -> Result<String> {
                let json = abieos.hex_to_json("eosio", "transaction", PACKED)?;
                let hex_out = abieos.json_to_hex("eosio", "transaction", &json)?;
                assert_eq!(hex_out.to_ascii_lowercase(),PACKED);
                Ok(json)
            }();
            abieos.destroy();
        }
        Ok(())
    }

    fn _char_to_hex(c: &u8) -> Result<String> {
        let mut r: [u8; 2] = [0; 2];
        let b1_1 = c & 0xf0;
        let b1 = b1_1.checked_shr(4).unwrap_or(0);
        if b1 > 10 {
            r[0] = b1 -10 + 'a' as u8;
        } else {
            r[0] = b1 + '0' as u8;
        }
        let b1 = c & 0x0f;
        if b1 > 10 {
            r[1] = b1 -10 + 'a' as u8;
        } else {
            r[1] = b1 + '0' as u8;
        }
        Ok(String::from_utf8(r.to_vec())?)
    }
}
