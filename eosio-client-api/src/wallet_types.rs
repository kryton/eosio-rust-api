/**
* This contains the interfaces used in chatting to KleosD.
* This is temporary used to sign things (transactions, digests) until eos-keys gains the ability to
* perform cannonical signatures
*/
//use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
//use crate::api_types::eosio_datetime_format;
use crate::errors::{Result, ErrorKind};
use crate::json_rpc::{EOSRPC};
use serde_json::Value;
use eosio_client_keys::{EOSPublicKey, EOSPrivateKey};

use crate::api_types::{TransactionIn, TransactionInSigned, vec_u8_to_hex};

const WALLET_UNLOCKED_EXCEPTION: usize = 3_120_007;
#[allow(dead_code)]
pub const EOSIO_CHAIN_ID: &str = "cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f";

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletList {
    name: String
}

pub struct Wallet {
    keos: EOSRPC,
    chain_id: Option<String>,
}

impl Wallet {
    pub fn create(keos: EOSRPC) -> Wallet {
        Wallet { keos, chain_id: None }
    }
    pub fn create_with_chain_id(keos: EOSRPC, chain_id: &str) -> Wallet {
        Wallet { keos, chain_id: Some(String::from(chain_id)) }
    }
    pub fn list(&self) -> Result<Vec<String>> {
        let value = serde_json::json!({ "cookie": "monster" });
        let res = self.keos.blocking_req("/v1/wallet/list_wallets", value)?;
        let list: Vec<String> = serde_json::from_str(&res).unwrap();

        Ok(list)
    }
    pub fn keys(&self) -> Result<Vec<EOSPublicKey>> {
        let value = serde_json::json!({ "cookie": "monster" });
        let res = self.keos.blocking_req("/v1/wallet/get_public_keys", value)?;
        let list: Vec<String> = serde_json::from_str(&res).unwrap();
        let keys = EOSPublicKey::from_eos_strings(&list)?;

        Ok(keys)
    }
    pub fn private_keys(&self, wallet: &str, pass: &str) -> Result<Vec<(EOSPublicKey, EOSPrivateKey)>> {
        let value = serde_json::json!([wallet, pass ]);
        let res = self.keos.blocking_req("/v1/wallet/list_keys", value)?;
        let list: Vec<(String, String)> = serde_json::from_str(&res).unwrap();
        let mut r: Vec<(EOSPublicKey, EOSPrivateKey)> = vec![];
        for pair in list {
            let public: EOSPublicKey = EOSPublicKey::from_eos_string(&pair.0)?;
            let private: EOSPrivateKey = EOSPrivateKey::from_string(&pair.1)?;
            r.push((public, private));
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
            }
            Err(e) => {
                match e.0 {
                    ErrorKind::InvalidResponseStatus(k) => {
                        if k.code == WALLET_UNLOCKED_EXCEPTION {
                            Ok(true)
                        } else {
                            eprintln!("{:#?}", k);
                            Err("Fail-Wallet Unlock".into())
                        }
                    }
                    _ => {
                        eprintln!("{:#?}", e);
                        panic!("Wallet unlock Fail");
                    }
                }
            }
        }
    }
    pub fn sign_transaction(&self, transaction: TransactionIn, pubkey: Vec<EOSPublicKey>) -> Result<TransactionInSigned> {
        let mut pubkey_str: Vec<String> = vec![];
        for k in pubkey {
            pubkey_str.push(k.to_eos_string()?)
        }
        if self.chain_id.is_none() {
            Err(ErrorKind::WalletMissingChainID.into())
        } else {
            let value = serde_json::json![[transaction, pubkey_str, self.chain_id.as_ref().unwrap()]];
            let res = self.keos.blocking_req("/v1/wallet/sign_transaction", value)?;
            let t: TransactionInSigned = serde_json::from_str(&res).unwrap();
            Ok(t)
        }
    }

    pub fn sign_digest(&self, digest: &[u8], pubkey: &EOSPublicKey) -> Result<String> {
        let digest_b = vec_u8_to_hex(digest)?;
        let value = serde_json::json![[digest_b, pubkey.to_eos_string()?]];
        let res = self.keos.blocking_req("/v1/wallet/sign_digest", value)?;
        let sig: String = serde_json::from_str(&res).unwrap();
        Ok(sig)
    }
}
#[allow(dead_code)]
pub fn get_wallet_pass() -> Result<String> {
    use std::fs;
    let pass = String::from(fs::read_to_string(".env")?.trim());
    Ok(pass)
}

#[cfg(test)]
mod test {
    use super::*;
    use eosio_client_keys::hash::hash_sha256;
    use eosio_client_keys::EOSSignature;

    const KEOSD_HOST: &str = "http://127.0.0.1:3888";

    #[test]
    fn wallet_list_test() -> Result<()> {
        let keos = EOSRPC::blocking( String::from(KEOSD_HOST) )?;
        let _wallets = Wallet::create(keos).list()?;

        Ok(())
    }

    #[test]
    fn wallet_list_unlock() -> Result<()> {
        let keos = EOSRPC::blocking( String::from(KEOSD_HOST) )?;
        let pass = get_wallet_pass()?;
        let _wallets = Wallet::create(keos).unlock("default", &pass)?;
        Ok(())
    }

    #[test]
    fn wallet_list_keys() -> Result<()> {
        let keos = EOSRPC::blocking( String::from(KEOSD_HOST) )?;
        let pass = get_wallet_pass()?;
        let wallet = Wallet::create(keos);
        let _wallets = wallet.unlock("default", &pass)?;
        let _keys = wallet.keys()?;

        Ok(())
    }

    #[test]
    fn wallet_list_private_keys() -> Result<()> {
        let keos = EOSRPC::blocking( String::from(KEOSD_HOST) )?;
        let pass = get_wallet_pass()?;
        let wallet = Wallet::create(keos);
        let _res = wallet.unlock("default", &pass)?;
        let keys = wallet.private_keys("default", &pass)?;
        for k in keys {
            assert_eq!(k.0.to_eos_string()?, k.1.to_public().to_eos_string()?);
        }
        Ok(())
    }

    #[test]
    fn wallet_sign_txn() -> Result<()> {
        let keos = EOSRPC::blocking( String::from(KEOSD_HOST) )?;
        let pass = get_wallet_pass()?;
        let wallet = Wallet::create_with_chain_id(keos, EOSIO_CHAIN_ID);
        let _res = wallet.unlock("default", &pass)?;
        let t = TransactionIn::dummy();
        let pubkey = EOSPublicKey::from_eos_string("EOS7ctUUZhtCGHnxUnh4Rg5eethj3qNS5S9fijyLMKgRsBLh8eMBB")?;
        let ti: TransactionInSigned = wallet.sign_transaction(t, vec![pubkey])?;
        let sigs = ti.signatures;
        assert_eq!(sigs.len(), 1);
        for sig in sigs {
            let eos_sig: EOSSignature = EOSSignature::from_string(&sig)?;
            if !eos_sig.is_canonical()  {
                eprintln!("{:#?}", eos_sig.to_eos_string());
            }
            assert!(eos_sig.is_canonical());
        }
        Ok(())
    }

    #[test]
    fn wallet_sign_digest() -> Result<()> {
        let keos = EOSRPC::blocking( String::from(KEOSD_HOST) )?;
        let pass = get_wallet_pass()?;
        let wallet = Wallet::create( keos);
        let _res = wallet.unlock("default", &pass)?;
        let pubkey = EOSPublicKey::from_eos_string("EOS7ctUUZhtCGHnxUnh4Rg5eethj3qNS5S9fijyLMKgRsBLh8eMBB")?;
        let phrase: Vec<u8> = "Greg! The Stop sign".as_bytes().to_vec();
        let hash = hash_sha256(&phrase);
        let sig = wallet.sign_digest(&hash, &pubkey)?;
        let eos_sig: EOSSignature = EOSSignature::from_string(&sig)?;
        eos_sig.verify_hash(&hash, &pubkey)?;
        assert!(eos_sig.is_canonical());

        Ok(())
    }
}
