/**
* This contains the interfaces used in chatting to KleosD.
* This is temporary used to sign things (transactions, digests) until eos-keys gains the ability to
* perform cannonical signatures
*/
//use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
//use crate::api_types::eosio_datetime_format;
use crate::errors::{Result, ErrorKind};
use crate::json_rpc::EOSRPC;
use serde_json::Value;
use eosio_keys::{EOSPublicKey,EOSPrivateKey};

const WALLET_UNLOCKED_EXCEPTION: usize = 3120007;

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletList {
    name: String
}

pub struct Wallet {
    keos: EOSRPC,
}

impl Wallet {
    pub fn list(&self) -> Result<Vec<String>> {
        let value = serde_json::json!({ "cookie": "monster" });
        let res = self.keos.blocking_req("/v1/wallet/list_wallets", value)?;
        let list: Vec<String> = serde_json::from_str(&res).unwrap();

        Ok(list)
    }
    pub fn keys(&self) -> Result<Vec<EOSPublicKey>> {
        let value = serde_json::json!({ "cookie": "monster" });
        let res = self.keos.blocking_req("/v1/wallet/get_public_keys", value)?;
        let list: Vec<&str> = serde_json::from_str(&res).unwrap();
        let keys = EOSPublicKey::from_eos_strings(list)?;

        Ok(keys)
    }
    pub fn private_keys(&self, wallet:&str, pass: &str) -> Result<Vec<(EOSPublicKey,EOSPrivateKey)>> {
        let value = serde_json::json!([wallet, pass ]);
        let res = self.keos.blocking_req("/v1/wallet/list_keys", value)?;
        let list: Vec<(String,String)> = serde_json::from_str(&res).unwrap();
        let mut r: Vec<(EOSPublicKey,EOSPrivateKey)> = vec![];
        for pair in list {
            let public:EOSPublicKey = EOSPublicKey::from_eos_string( &pair.0)?;
            let private:EOSPrivateKey = EOSPrivateKey::from_string( &pair.1)?;
            r.push((public,private));
        }

        Ok(r)
    }

    pub fn unlock(&self, wallet: &str, pass: &str) -> Result<bool> {
        let value = serde_json::json!([ wallet, pass ]);
        match self.keos.blocking_req("/v1/wallet/unlock", value) {
            Ok(res) => {
                let resp: Value = serde_json::from_str(&res).unwrap();
                if resp.is_object() {
                    Ok(true)
                } else {
                    Err("Fail-Wallet Unlock unknown response".into())
                }
            },
            Err(e) => {
                match e.0 {
                    ErrorKind::InvalidResponseStatus(k) => {
                        if k.code == WALLET_UNLOCKED_EXCEPTION {
                             Ok(true)
                        } else {
                            eprintln!("{:#?}", k);
                            Err("Fail-Wallet Unlock".into())
                        }
                    },
                    _ => {
                        eprintln!("{:#?}", e);
                        assert!(false);
                        Err("Fail-Wallet Unlock".into())
                    }
                }
            }
        }
    }
}
#[cfg(test)]
mod test {
    use super::*;

    const KEOSD_HOST: &str = "http://127.0.0.1:3999";
    fn get_wallet_pass() ->Result<String> {
        use std::fs;
        let pass =String::from( fs::read_to_string(".env")?.trim());
        Ok(pass)
    }
    #[test]
    fn wallet_list_test() -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let keos = EOSRPC { client, host: String::from(KEOSD_HOST) };
        let wallets  = Wallet{keos}.list()?;

        Ok(())
    }
    #[test]
    fn wallet_list_unlock() -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let keos = EOSRPC { client, host: String::from(KEOSD_HOST) };
        let pass = get_wallet_pass()?;
        let wallets  = Wallet{keos}.unlock("default",&pass)?;
        Ok(())
    }
    #[test]
    fn wallet_list_keys() -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let keos = EOSRPC { client, host: String::from(KEOSD_HOST) };

        let keys  = Wallet{keos}.keys()?;

        Ok(())
    }
    #[test]
    fn wallet_list_private_keys() -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let keos = EOSRPC { client, host: String::from(KEOSD_HOST) };
        let pass = get_wallet_pass()?;

        let keys  = Wallet{keos}.private_keys("default", &pass)?;
        for k in keys {
            assert_eq!(k.0.to_eos_string()?,k.1.to_public().to_eos_string()?);
        }
        Ok(())
    }

}
