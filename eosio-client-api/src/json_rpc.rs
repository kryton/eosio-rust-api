use crate::api_types::*;
use crate::errors::{Error, ErrorKind, Result};
use crate::wallet_types::Wallet;
use crate::wasm::WASM;
use eosio_client_keys::EOSPublicKey;
use libabieos_sys::{AbiFiles, ABIEOS};
use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::Value;
//use rust_embed::RustEmbed;

use chrono::{DateTime, Utc};

pub const ERROR_TXN_SET_EXACT_CODE: usize = 3_160_008;

pub struct EOSRPC {
    pub client: Client,
    pub host: String,
    pub abi_abi_js: String,
    pub transaction_abi_js: String,
}

impl EOSRPC {
    pub fn blocking(host: String) -> Result<EOSRPC> {
        let client = reqwest::blocking::Client::new();
        let abi_f = AbiFiles::get("abi_rv.abi.json").unwrap();
        let abi_abi_js: String = String::from_utf8(abi_f.as_ref().to_vec())?;
        let transaction_abi_js: String = String::from_utf8(
            AbiFiles::get("transaction.abi.json")
                .unwrap()
                .as_ref()
                .to_vec(),
        )?;
        Ok(EOSRPC {
            client,
            host,
            abi_abi_js,
            transaction_abi_js,
        })
    }

    pub fn blocking_ex(host: String, abi_abi_js: &str, transaction_abi_js: &str) -> EOSRPC {
        let client = reqwest::blocking::Client::new();
        EOSRPC {
            client,
            host,
            abi_abi_js: abi_abi_js.to_string(),
            transaction_abi_js: transaction_abi_js.to_string(),
        }
    }

    pub fn blocking_req(&self, url: &str, in_json: Value) -> Result<String> {
        let full_url = [&self.host, url].concat();
        let req = self.client.post(&full_url).json(&in_json);
        let response = req.send()?;
        let content_type = response.headers().get(CONTENT_TYPE).unwrap();
        let hv_json = HeaderValue::from_static("application/json");
        if content_type != hv_json {
            return Err(ErrorKind::InvalidResponseContentType.into());
        }
        let status = response.status();

        if status == StatusCode::OK
            || status == StatusCode::CREATED
            || status == StatusCode::ACCEPTED
        {
            Ok(response.text()?)
        } else {
            let tx: &str = &response.text()?;
            let msg: ErrorReply = serde_json::from_str(tx).unwrap();
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
        let value = serde_json::json!({ });


        let res = self.blocking_req("/v1/chain/get_info", value)?;
        let ga: GetInfo = serde_json::from_str(&res).unwrap();
        Ok(ga)
    }

    pub fn get_code_hash(&self, account_name: &str) -> Result<GetCodeHash> {
        let value = serde_json::json!({ "account_name": account_name });

        let res = self.blocking_req("/v1/chain/get_code_hash", value)?;
        let gc: GetCodeHash = serde_json::from_str(&res)?;
        Ok(gc)
    }

    pub fn get_raw_abi(&self, account_name: &str) -> Result<GetRawABI> {
        let value = serde_json::json!({ "account_name": account_name });

        let res = self.blocking_req("/v1/chain/get_raw_abi", value)?;
        let gr: GetRawABI = serde_json::from_str(&res)?;
        Ok(gr)
    }
    pub fn get_block_num(&self, block_num: usize) -> Result<GetBlock> {
        let value = serde_json::json!({ "block_num_or_id": block_num });

        let res = self.blocking_req("/v1/chain/get_block", value)?;
        let gb: GetBlock = serde_json::from_str(&res)?;
        Ok(gb)
    }
    pub fn get_block_id(&self, block_id: &str) -> Result<GetBlock> {
        let value = serde_json::json!({ "block_num_or_id": block_id });

        let res = self.blocking_req("/v1/chain/get_block", value)?;
        let gb: GetBlock = serde_json::from_str(&res)?;
        Ok(gb)
    }

    pub fn get_required_keys(
        &self,
        transaction: &TransactionIn,
        keys: Vec<EOSPublicKey>,
    ) -> Result<RequiredKeys> {
        let mut key_str: Vec<String> = vec![];
        for key in keys {
            let x = key.to_eos_string()?;
            key_str.push(x);
        }

        let value = serde_json::json!({ "transaction": transaction, "available_keys":key_str});
        let res = self.blocking_req("/v1/chain/get_required_keys", value)?;
        let rk: RequiredKeys = serde_json::from_str(&res).unwrap();
        Ok(rk)
    }

    pub fn get_abi_from_account(
        &self,
        abieos_eosio: &ABIEOS,
        account_name: &str,
    ) -> Result<ABIEOS> {
        let rawabi_r = self.get_raw_abi(account_name);
        let account_abi = rawabi_r?.decode_abi()?;

        let account_abi_json = abieos_eosio.bin_to_json("eosio", "abi_def", &account_abi)?;
        Ok(ABIEOS::new_with_abi(account_name, &account_abi_json)?)
    }

    pub fn push_transaction(
        &self,
        abieos: &ABIEOS,
        wallet: &Wallet,
        actions: Vec<ActionIn>,
        ref_block: &str,
        exp_time: DateTime<Utc>,
    ) -> Result<TransactionResponse> {
        let ti = TransactionIn::simple(actions, ref_block, exp_time)?;

        let trx_json = serde_json::to_string(&ti)?;
        let trx = abieos.json_to_hex("eosio", "transaction", &trx_json)?;

        let pubkeys = wallet.keys()?;
        let required_keys = self.get_required_keys(&ti, pubkeys)?;
        let eospubs: Vec<EOSPublicKey> =
            EOSPublicKey::from_eos_strings(&required_keys.required_keys)?;

        let signed_transaction = wallet.sign_transaction(ti, eospubs)?;
        let pti = PackedTransactionIn {
            signatures: signed_transaction.signatures,
            compression: "none".to_string(),
            packed_context_free_data: "".to_string(),
            packed_trx: trx.to_string(),
        };

        let in_val = serde_json::json!(pti);
        let res = self.blocking_req("/v1/chain/push_transaction", in_val)?;
        let tr: TransactionResponse = serde_json::from_str(&res).unwrap();
        Ok(tr)
    }

    pub fn get_table_rows(
        &self,
        code: &str,
        scope: &str,
        table: &str,
        table_key: &str,
        lower_bound: &str,
        upper_bound: &str,
        limit: usize,
        key_type: &str,
        index_position: &str,
        encode_type: &str,
        reverse: bool,
        show_payer: bool,
    ) -> Result<GetTableRows> {
        let in_j = GetTableRowsIn {
            json: false,
            code: code.parse().unwrap(),
            scope: scope.parse().unwrap(),
            table: table.parse().unwrap(),
            table_key: table_key.parse().unwrap(),
            lower_bound: lower_bound.parse().unwrap(),
            upper_bound: upper_bound.parse().unwrap(),
            limit,
            key_type: key_type.parse().unwrap(),
            index_position: index_position.parse().unwrap(),
            encode_type: encode_type.parse().unwrap(),
            reverse,
            show_payer,
        };
        let in_val = serde_json::json!(in_j);
        let res = self.blocking_req("/v1/chain/get_table_rows", in_val)?;
        let tr: GetTableRows = serde_json::from_str(&res).unwrap();
        Ok(tr)
    }
    pub fn get_table_by_scope(
        &self,
        code: &str,
        table: &str,
        lower_bound: &str,
        upper_bound: &str,
        limit: usize,
        reverse: bool,
    ) -> Result<GetTableByScope> {
        let pti = GetTableByScopeIn {
            code: code.parse().unwrap(),
            table: table.parse().unwrap(),
            lower_bound: lower_bound.parse().unwrap(),
            upper_bound: upper_bound.parse().unwrap(),
            limit,
            reverse,
        };
        let in_val = serde_json::json!(pti);
        let res = self.blocking_req("/v1/chain/get_table_by_scope", in_val)?;
        let tr: GetTableByScope = serde_json::from_str(&res).unwrap();
        Ok(tr)
    }
}

pub fn create_setcode_action(acct_abieos: &ABIEOS, name: &str, code: &WASM) -> Result<ActionIn> {
    let auth = AuthorizationIn {
        permission: "active".to_string(),
        actor: String::from(name),
    };
    let v_auth: Vec<AuthorizationIn> = vec![auth];
    let data = ActionSetcodeData {
        account: String::from(name),
        vmtype: 0,
        vmversion: 0,
        code: vec_u8_to_hex(&code.code)?,
    }
    .to_hex(acct_abieos)?;

    Ok(ActionIn {
        name: "setcode".to_string(),
        account: "eosio".to_string(),
        authorization: v_auth,
        data,
    })
}

pub fn create_setcode_clear_action(acct_abieos: &ABIEOS, name: &str) -> Result<ActionIn> {
    let auth = AuthorizationIn {
        permission: "active".to_string(),
        actor: String::from(name),
    };
    let v_auth: Vec<AuthorizationIn> = vec![auth];
    let data = ActionSetcodeData {
        account: String::from(name),
        vmtype: 0,
        vmversion: 0,
        code: vec_u8_to_hex(&WASM::dummy())?,
    }
    .to_hex(acct_abieos)?;

    Ok(ActionIn {
        name: "setcode".to_string(),
        account: "eosio".to_string(),
        authorization: v_auth,
        data,
    })
}

pub struct AbiTrio {
    pub sys_abi: ABIEOS,
    pub txn_abi: ABIEOS,
    pub acct_abi: ABIEOS,
}

impl AbiTrio {
    pub fn create(sys_name: &str, sys_acct_name: &str, eos: &EOSRPC) -> Result<AbiTrio> {
        let sys_abi = ABIEOS::new_with_abi(sys_name, &eos.abi_abi_js)?;
        let txn_abi: ABIEOS =
            ABIEOS::new_with_abi(sys_name, &eos.transaction_abi_js).map_err(|e| {
                sys_abi.destroy();
                Error::with_chain(e, "AbiTrio_txn")
            })?;
        let acct_abi: ABIEOS = eos
            .get_abi_from_account(&sys_abi, sys_acct_name)
            .map_err(|e| {
                sys_abi.destroy();
                txn_abi.destroy();
                Error::with_chain(e, "AbiTrio_act")
            })?;

        Ok(AbiTrio {
            sys_abi,
            txn_abi,
            acct_abi,
        })
    }
    pub fn destroy(&self) {
        self.acct_abi.destroy();
        self.txn_abi.destroy();
        self.sys_abi.destroy()
    }
}

pub fn create_setabi_action(
    sys_abieos: &ABIEOS,
    acct_abieos: &ABIEOS,
    name: &str,
    abi: &str,
) -> Result<ActionIn> {
    let auth = AuthorizationIn {
        permission: "active".to_string(),
        actor: String::from(name),
    };
    let v_auth: Vec<AuthorizationIn> = vec![auth];
    let abi_hex = sys_abieos.json_to_hex("eosio", "abi_def", abi)?;
    // let abi_s = String::from(abi);
    let data = ActionSetData {
        account: String::from(name),
        abi: String::from(abi_hex),
    }
    .to_hex(acct_abieos)?;

    Ok(ActionIn {
        name: "setabi".to_string(),
        account: "eosio".to_string(),
        data,
        authorization: v_auth,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    //use crate::api_types::GetAccount;
    use crate::wallet_types::{get_wallet_pass, EOSIO_CHAIN_ID};
    use chrono::{Duration, NaiveDateTime};
    use std::fs;

    //const TEST_HOST: &str = "http://127.0.0.1:8888";
    const TEST_HOST: &str = "http://tempest.local:8888";
    //const TEST_HOST: &str = "https://api.testnet.eos.io";
    const TEST_KEOSD: &str = "http://127.0.0.1:3888";

    const TEST_WALLET_NAME: &str = "default";
    const TEST_ACCOUNT_NAME: &str = "fwonhjnefmps";

    //const TEST_HOST: &str = "https://eos.greymass.com";
    //const TEST_HOST: &str = "https://chain.wax.io";

    #[test]
    fn blocking_req_test() -> Result<()> {
        let eos = EOSRPC::blocking(String::from(TEST_HOST))?;
        let _ga = eos.get_account("eosio")?;

        let _abi = eos.get_abi("eosio")?;
        Ok(())
    }

    #[test]
    fn blocking_get_info() -> Result<()> {
        let eos = EOSRPC::blocking(String::from(TEST_HOST))?;
        let _gi = eos.get_info()?;
        Ok(())
    }

    #[test]
    fn datetime_format() {
        let s = "2020-05-16T05:12:03";
        const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S";
        // let _tz_offset = FixedOffset::east(0);
        match NaiveDateTime::parse_from_str(s, FORMAT) {
            Err(_e) => {
                eprintln!("{:#?}", _e);
                assert!(false)
            }
            Ok(_dt) => assert!(true),
        }
    }

    #[test]
    fn blocking_get_required_keys() -> Result<()> {
        //  let client = reqwest::blocking::Client::new();
        let eos = EOSRPC::blocking(String::from(TEST_HOST))?;
        let keys = vec![
            EOSPublicKey::from_eos_string("EOS6zUgp7uAV1pCTXZMGJyH3dLUSWJUkZWGA9WpWxyP2pCT3mAkNX")
                .unwrap(),
            EOSPublicKey::from_eos_string("EOS7ctUUZhtCGHnxUnh4Rg5eethj3qNS5S9fijyLMKgRsBLh8eMBB")
                .unwrap(),
            EOSPublicKey::from_eos_string("EOS8fdsPr1aKsmszNHeY4RrgupbabNQ5nmLgQWMEkTn2dENrPbRgP")
                .unwrap(),
        ];
        let gi: GetInfo = eos.get_info()?;
        let exp_time = gi.set_exp_time(Duration::seconds(1800));

        let wasm = WASM::read_file("test/good-2.wasm")?;

        let name = TEST_ACCOUNT_NAME;

        let abi_trio = AbiTrio::create("eosio", "eosio", &eos)?;
        let action_r = create_setcode_action(&abi_trio.acct_abi, &name, &wasm);
        abi_trio.destroy();

        let ti = TransactionIn::simple(vec![action_r?], &gi.last_irreversible_block_id, exp_time)?;
        let rk = eos.get_required_keys(&ti, keys)?;
        assert!(rk.required_keys.len() > 0);
        let k = &rk.required_keys[0];

        // accidentally set one of chains to have 'owner' key instead of 'active'
        if k == "EOS7ctUUZhtCGHnxUnh4Rg5eethj3qNS5S9fijyLMKgRsBLh8eMBB" {
            ()
        } else {
            assert_eq!(k, "EOS8fdsPr1aKsmszNHeY4RrgupbabNQ5nmLgQWMEkTn2dENrPbRgP");
        }
        Ok(())
    }

    /// these two need some static thing which will exist over all test environments
    /// the TicTacToe example deletes ALL of it's data on successful completion, so can't really be
    /// used
    ///
    #[test]
    fn blocking_table_rows() -> Result<()> {
        let eos = EOSRPC::blocking(String::from(TEST_HOST))?;
        let _r = eos.get_table_rows(
            TEST_ACCOUNT_NAME,
            "tictactoe",
            "games",
            "",
            "",
            "",
            10,
            "",
            "",
            "dec",
            false,
            true,
        );
        Ok(())
    }

    /// these two need some static thing which will exist over all test environments
    /// the TicTacToe example deletes ALL of it's data on successful completion, so can't really be
    /// used
    ///
    #[test]
    fn blocking_table_by_scope() -> Result<()> {
        let eos = EOSRPC::blocking(String::from(TEST_HOST))?;
        let _r = eos.get_table_by_scope("eosio.token", "", TEST_ACCOUNT_NAME, "", 10, false);
        Ok(())
    }

    #[test]
    fn blocking_push_txn() -> Result<()> {
        let eos = EOSRPC::blocking(String::from(TEST_HOST))?;
        let wallet = Wallet::create_with_chain_id(
            EOSRPC::blocking(String::from(TEST_KEOSD))?,
            EOSIO_CHAIN_ID,
        );
        let wallet_pass = get_wallet_pass()?;
        wallet.unlock(&TEST_WALLET_NAME, &wallet_pass)?;
        let wasm = WASM::read_file("test/good-2.wasm")?;
        let wasm_abi = fs::read_to_string("test/good-2.abi")?;

        let name = TEST_ACCOUNT_NAME;

        let gi: GetInfo = eos.get_info()?;
        let exp_time = gi.set_exp_time(Duration::seconds(1800));
        let abi_trio = AbiTrio::create("eosio", "eosio", &eos)?;

        let action_clear = create_setcode_clear_action(&abi_trio.acct_abi, &name).map_err(|e| {
            abi_trio.destroy();
            Error::with_chain(e, "blocking_push_txn/create_setcode_clear_action")
        })?;

        let _res_clear_int = eos
            .push_transaction(
                &abi_trio.txn_abi,
                &wallet,
                vec![action_clear],
                &gi.head_block_id,
                exp_time,
            )
            .map_err(|e| {
             //   abi_trio.destroy();
                Error::with_chain(e, "blocking_push_txn/push_transaction(clear)")
            });
        if _res_clear_int.is_err() {
            eprintln!("Ignoring error for clearing contract - {:#?}", _res_clear_int.err().unwrap())
        }

        let action = create_setcode_action(&abi_trio.acct_abi, &name, &wasm).map_err(|e| {
            abi_trio.destroy();
            Error::with_chain(e, "blocking_push_txn/create_setcode_action")
        })?;
        let action_abi =
            create_setabi_action(&abi_trio.sys_abi, &abi_trio.acct_abi, &name, &wasm_abi).map_err(
                |e| {
                    abi_trio.destroy();
                    Error::with_chain(e, "blocking_push_txn/create_setabi_action")
                },
            )?;

        let _res_int = eos
            .push_transaction(
                &abi_trio.txn_abi,
                &wallet,
                vec![action, action_abi],
                &gi.head_block_id,
                exp_time,
            )
            .map_err(|e| {
                abi_trio.destroy();
                Error::with_chain(e, "blocking_push_txn/push_transaction(set-code/abi)")
            })?;

        abi_trio.destroy();
        Ok(())
    }

    #[test]
    fn blocking_get_raw_abi() -> Result<()> {
        let eos = EOSRPC::blocking(String::from(TEST_HOST))?;
        let _res = eos.get_raw_abi("eosio")?;

        Ok(())
    }

    #[test]
    fn blocking_getsetabi() -> Result<()> {
        let eos = EOSRPC::blocking(String::from(TEST_HOST))?;
        let wasm_abi = fs::read_to_string("test/good-2.abi")?;
        let wallet = Wallet::create_with_chain_id(
            EOSRPC::blocking(String::from(TEST_KEOSD))?,
            EOSIO_CHAIN_ID,
        );
        let wallet_pass = get_wallet_pass()?;
        wallet.unlock(&TEST_WALLET_NAME, &wallet_pass)?;
        let gi = eos.get_info()?;
        let exp_time = gi.set_exp_time(Duration::seconds(1800));

        let name = TEST_ACCOUNT_NAME;
        let trio = AbiTrio::create("eosio", "eosio", &eos)?;

        let action_abi = create_setabi_action(&trio.sys_abi, &trio.acct_abi, &name, &wasm_abi)
            .map_err(|e| {
                &trio.destroy();
                Error::with_chain(e, "create_setabi_action")
            })?;

        let _tr = eos
            .push_transaction(
                &trio.txn_abi,
                &wallet,
                vec![action_abi],
                &gi.head_block_id,
                exp_time,
            )
            .map_err(|e| {
                trio.destroy();
                Error::with_chain(e, "push_transaction")
            })?;
        trio.destroy();

        // if the abi is written incorrectly this will cause a server error
        let _get_abi = eos.get_abi(name)?;

        Ok(())
    }

    #[test]
    fn block_getblock() -> Result<()> {
        let eos = EOSRPC::blocking(String::from(TEST_HOST))?;
        let block = eos.get_block_num(1)?;
        let block2 = eos.get_block_id(&block.id)?;
        assert_eq!(block.block_num, block2.block_num);
        Ok(())
    }
}
