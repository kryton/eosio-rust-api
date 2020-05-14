//use crate::errors::{Result, ErrorKind};

//extern crate reqwest;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::Value;
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use crate::errors::{Result, ErrorKind};
use crate::api_types::{GetAccount, GetAbi, RequiredKeys, GetInfo, TransactionIn, ActionIn, AuthorizationIn, ErrorReply, PackedTransactionIn};
//use serde::Deserialize;
use eosio_keys::{EOSPublicKey, EOSPrivateKey, EOSSignature};
use crate::wasm::WASM;
use crate::abi::ABIName;
use crate::numeric::binary_to_base58;


pub struct EOSRPC {
    client: Client,
    host: String,
}

impl EOSRPC {
    fn blocking_req(&self, url: &str, in_json: Value) -> Result<String> {
        let full_url = [&self.host, url].concat();
        let req = self.client.post(&full_url).json(&in_json);
        let response = req.send()?;
        let content_type = response.headers().get(CONTENT_TYPE).unwrap();
        let hv_json = HeaderValue::from_static("application/json");
        if content_type != hv_json {
            return Err(ErrorKind::InvalidResponseContentType.into());
        }
        let status = response.status();
        if status == StatusCode::OK {
            Ok(response.text()?)
        } else {
            // TODO return the JSON error
            let msg:ErrorReply = serde_json::from_str(&response.text()?).unwrap();
            //eprintln!("{}",msg);
            Err(ErrorKind::InvalidResponseStatus(msg.error).into())
        }
    }

    pub fn get_account(&self, account_name: &str) -> Result<GetAccount> {
        let value = serde_json::json!({ "account_name": account_name });
        let res = self.blocking_req("/v1/chain/get_account", value)?;
        let ga: GetAccount = serde_json::from_str(&res).unwrap();
        Ok(ga)
    }
    pub fn get_abi(&self, account_name: &str) -> Result<GetAbi> {
        let value = serde_json::json!({ "account_name": account_name });
        let res = self.blocking_req("/v1/chain/get_abi", value)?;
        let ga: GetAbi = serde_json::from_str(&res).unwrap();
        Ok(ga)
    }

    pub fn get_info(&self) -> Result<GetInfo> {
        let value = serde_json::json!({ "this is": "the future" });

        let res = self.blocking_req("/v1/chain/get_info", value)?;
        let ga: GetInfo = serde_json::from_str(&res).unwrap();
        Ok(ga)
    }
    // TODO
    pub fn get_required_keys(&self, transaction: &TransactionIn, keys: Vec<EOSPublicKey>) -> Result<RequiredKeys> {
        let mut key_str: Vec<String> = vec![];
        for key in keys {
            let x = key.to_eos_string()?;
            key_str.push(x);
        }

        let value = serde_json::json!({ "transaction": transaction, "available_keys":key_str});
        let res = self.blocking_req("/v1/chain/get_required_keys", value)?;
        let ga: RequiredKeys = serde_json::from_str(&res).unwrap();
        Ok(ga)
    }

    pub fn push_transaction(&self, private_key: EOSPrivateKey, transaction: &TransactionIn) -> Result<()> {

        let packed_trx = serde_json::to_string(transaction)?;
        let sig: EOSSignature = private_key.sign(packed_trx.as_bytes())?;
        let sig_str = sig.to_eos_string().unwrap();
        eprintln!("SIG {} {}", sig_str,sig_str.len());
        //let trx = vec_u8_to_str(packed_trx.as_bytes().to_vec())?;
        let trx = binary_to_base58(packed_trx.as_bytes().to_vec(),12);
        let in_val = serde_json::json!(PackedTransactionIn{
            signatures: vec![sig_str],
            compression: "none".to_string(),
            packed_context_free_data: "".to_string(),
            packed_trx: trx,
        });
        
        match self.blocking_req("/v1/chain/push_transaction", in_val) {
            Err(e) => {
                eprintln!("{:#?}",e);
                assert!(false)
            },
            Ok(s) => {
                eprintln!("{}",s)
            }
        }

        Ok(())
    }
}

struct ActionSetcodeData {
    name: ABIName,
    vmtype: u8,
    vmversion: u8,
    wasm: WASM,
}

fn byte_to_char(x: u8) -> char {
    (if x <= 9 {
        x + '0' as u8
    } else {
        x - 10 + 'a' as u8
    }) as char
}
pub fn vec_u8_to_str(out: Vec<u8>) -> Result<String> {

    let mut str = String::with_capacity(out.len());
    for x in out {
        str.push(byte_to_char((x & 0xf0).checked_shr(4).unwrap_or(0)));
        str.push(byte_to_char(x & 0x0f));
    }
    Ok(str)
}
impl ActionSetcodeData {
    fn to_str(&self) -> Result<String> {
        let code_len = self.wasm.code.len();
        let buf = self.name.value.to_ne_bytes().to_vec();
        // let out:Vec<u8> = Vec::<u8>::with_capacity(code_len+buf.len()+2);
        let vm: Vec<u8> = [self.vmtype, self.vmversion].to_vec();
        let c = self.wasm.code.to_vec();
        let out = [buf, vm, c].concat();
        Ok(vec_u8_to_str(out)?)
            /*
       let mut str = String::with_capacity(code_len + 13 + 2);

        for x in out {
            str.push(byte_to_char((x & 0xf0).checked_shr(4).unwrap_or(0)));
            str.push(byte_to_char(x & 0x0f));
        }
        Ok(str)

             */
    }
}

pub fn create_setcode_action(name: ABIName, code: WASM) -> Result<ActionIn> {
    let auth = AuthorizationIn { permission: "active".to_string(), actor: name.to_str()? };
    let v_auth: Vec<AuthorizationIn> = vec![auth];
    let data = ActionSetcodeData { name, vmtype: 0, vmversion: 0, wasm: code }.to_str()?;

    Ok(ActionIn {
        name: "setcode".to_string(),
        account: "eosio".to_string(),
        data: data,
        authorization: v_auth,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    //use reqwest::blocking::RequestBuilder;

    use crate::api_types::GetAccount;

   // const TEST_HOST: &str = "http://127.0.0.1:8888";
    const TEST_HOST: &str = "https://api.testnet.eos.io";
    //const TEST_HOST: &str = "https://eos.greymass.com";
    //const TEST_HOST: &str = "https://chain.wax.io";

    #[test]
    fn blocking_req_test() {
        let client = reqwest::blocking::Client::new();
        let eos = EOSRPC { client, host: String::from(TEST_HOST) };
        let ga = eos.get_account("eosio").unwrap();

        let abi = eos.get_abi("eosio").unwrap();
        //  eprintln!("{:#?}", abi);
    }

    #[test]
    fn blocking_get_info() {
        let client = reqwest::blocking::Client::new();
        let eos = EOSRPC { client, host: String::from(TEST_HOST) };
        let gi = eos.get_info().unwrap();
        // eprintln!("{:#?}", gi);
    }

    use chrono::{Utc, NaiveDateTime, FixedOffset, TimeZone, Duration};


    #[test]
    fn datetime_format() {
        let s = "2020-05-16T05:12:03";
        const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S";
        let tz_offset = FixedOffset::east(0);
        match NaiveDateTime::parse_from_str(s, FORMAT) {
            Err(_e) => {
                eprintln!("{:#?}", _e);
                assert!(false)
            }
            Ok(dt) => {
                assert!(true)
            }
        };
    }

    #[test]
    fn blocking_get_required_keys() -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let eos = EOSRPC { client, host: String::from(TEST_HOST) };

        let keys = vec![
            EOSPublicKey::from_eos_string("EOS6zUgp7uAV1pCTXZMGJyH3dLUSWJUkZWGA9WpWxyP2pCT3mAkNX").unwrap(),
            EOSPublicKey::from_eos_string("EOS7ctUUZhtCGHnxUnh4Rg5eethj3qNS5S9fijyLMKgRsBLh8eMBB").unwrap(),
        ];
        let gi:GetInfo = eos.get_info()?;
        let exp_time = gi.head_block_time +  Duration::days(1);
        match WASM::read_file("test/good.wasm") {
            Err(_) => assert!(false),
            Ok(wasm) => {
                let name = ABIName::from_str("fwonhjnefmps").unwrap();
                let action = create_setcode_action(name, wasm)?;
                let ti = TransactionIn::simple(action, gi.head_block_num, 0, exp_time);
                let rk = eos.get_required_keys(&ti, keys).unwrap();
                eprintln!("{:#?}", rk);
            }
        }
        Ok(())
    }
    #[test]
    fn blocking_push_txn() -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let eos = EOSRPC { client, host: String::from(TEST_HOST) };
        let gi:GetInfo = eos.get_info()?;
        let exp_time = gi.head_block_time + Duration::days(1);

        let key = EOSPrivateKey::from_string("PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd")?;
        let wasm = WASM::read_file("test/good.wasm")?;

        let name = ABIName::from_str("fwonhjnefmps").unwrap();
        let action = create_setcode_action(name, wasm)?;
        let ti = TransactionIn::simple(action, gi.head_block_num, 0, exp_time);
        let res = eos.push_transaction(key,&ti)?;
        eprintln!("{:#?}", "hi");


        Ok(())
    }
}

