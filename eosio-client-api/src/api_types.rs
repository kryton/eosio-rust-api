use crate::errors::Result;
use chrono::{DateTime, Duration, Utc};
use libabieos_sys::{eosio_datetime_format, ABIEOS};
use serde::{Deserialize, Serialize};

fn byte_to_char(x: u8) -> char {
    (if x <= 9 { x + b'0' } else { x - 10 + b'a' }) as char
}

pub fn vec_u8_to_hex(out: &[u8]) -> Result<String> {
    let mut str = String::with_capacity(out.len());
    for x in out {
        str.push(byte_to_char((x & 0xf0).checked_shr(4).unwrap_or(0)));
        str.push(byte_to_char(x & 0x0f));
    }
    Ok(str)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceLimit {
    pub max: isize,
    pub available: isize,
    pub used: isize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Key {
    pub key: String,
    pub weight: isize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Permission {
    pub permission: String,
    pub actor: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub weight: isize,
    pub permission: Permission,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequiredAuth {
    pub waits: Vec<String>,
    pub threshold: isize,
    pub accounts: Vec<Account>,
    pub keys: Vec<Key>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Permissions {
    pub parent: String,
    pub perm_name: String,
    pub required_auth: RequiredAuth,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VoterInfo {
    pub producers: Vec<String>,
    pub is_proxy: isize,
    pub owner: String,
    // staked: usize, Wax holds this as a string, EOS is a usize
    pub proxy: String,
    pub flags1: isize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetAccount {
    pub account_name: String,
    pub head_block_num: usize,
    pub privileged: bool,
    #[serde(with = "eosio_datetime_format")]
    pub last_code_update: DateTime<Utc>,
    #[serde(with = "eosio_datetime_format")]
    pub head_block_time: DateTime<Utc>,
    #[serde(with = "eosio_datetime_format")]
    pub created: DateTime<Utc>,
    pub core_liquid_balance: Option<String>,
    pub ram_quota: isize,
    pub net_weight: isize,
    pub cpu_weight: isize,
    pub ram_usage: usize,
    pub cpu_limit: ResourceLimit,
    pub net_limit: ResourceLimit,
    pub voter_info: Option<VoterInfo>,
    pub refund_request: Option<String>,
    pub permissions: Vec<Permissions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiTypes {
    pub new_type_name: String,
    #[serde(rename = "type")]
    pub abi_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiField {
    pub name: String,
    #[serde(rename = "type")]
    pub abi_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiStruct {
    pub name: String,
    pub base: String,
    pub fields: Vec<AbiField>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiAction {
    pub name: String,
    #[serde(rename = "type")]
    pub abi_type: String,
    pub ricardian_contract: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiTable {
    pub name: String,
    #[serde(rename = "type")]
    pub abi_type: String,
    pub index_type: String,
    pub key_names: Vec<String>,
    pub key_types: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiRicardianClauses {
    pub id: String,
    pub body: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiErrorMessages {
    pub error_code: String,
    pub error_msg: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiExtensions {
    pub tag: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiVariants {
    pub name: String,
    pub types: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Abi {
    pub version: String,
    pub types: Vec<AbiTypes>,
    pub structs: Vec<AbiStruct>,
    pub actions: Vec<AbiAction>,
    pub tables: Vec<AbiTable>,
    pub ricardian_clauses: Vec<AbiRicardianClauses>,
    pub error_messages: Vec<AbiErrorMessages>,
    pub abi_extensions: Vec<AbiExtensions>,
    pub variants: Vec<AbiVariants>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetAbi {
    pub account_name: String,
    pub abi: Abi,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequiredKeys {
    pub required_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetInfo {
    server_version: String,
    pub chain_id: String,
    pub head_block_num: usize,
    pub last_irreversible_block_num: usize,
    pub last_irreversible_block_id: String,
    pub head_block_id: String,
    #[serde(with = "eosio_datetime_format")]
    pub head_block_time: DateTime<Utc>,
    pub head_block_producer: String,
    pub virtual_block_cpu_limit: usize,
    pub virtual_block_net_limit: usize,
    pub block_cpu_limit: usize,
    pub block_net_limit: usize,
    pub server_version_string: String,
    pub fork_db_head_block_num: usize,
    pub fork_db_head_block_id: String,
    pub server_full_version_string: Option<String>,
}

impl GetInfo {
    pub fn set_exp_time(&self, duration: Duration) -> DateTime<Utc> {
        self.head_block_time + duration
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationIn {
    pub actor: String,
    pub permission: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCodeHash {
    pub account_name: String,
    pub code_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionIn {
    pub account: String,
    pub name: String,
    pub authorization: Vec<AuthorizationIn>,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionInSigned {
    #[serde(with = "eosio_datetime_format")]
    pub expiration: DateTime<Utc>,
    pub ref_block_num: u16,
    pub ref_block_prefix: u32,
    pub max_net_usage_words: u32,
    pub max_cpu_usage_ms: u8,
    pub delay_sec: u32,
    pub context_free_actions: Vec<String>,
    pub actions: Vec<ActionIn>,
    pub transaction_extensions: Vec<String>,
    pub signatures: Vec<String>, // KleosD 2.1 returns signatures here
}

/***
 Be aware. The ordering of this struct is important.
 EOSIO (abieos) expects the fields in the same order as shown in transaction.abi.json, and does not
 handle extra fields either.

 ref_block_num & ref_block_prefix are derived from the last_irreversible_block_id. retrieved from
 the get_info call.

--> thank you to @arhag for the detailed explanation.

if I use the last_irreversible_block_id from getinfo — (I added the '-' for clarity)
“0000daabcc9912b6-2359def6033b0463-d3a605c0ba7d6c77-9452ed321649db15”
The block ID modifies the hash of the block header such that its first 4 bytes represents the block
height as a big endian number. This is so that when it is printed out as a hex string, one could
just grab the first 8 hex characters to quickly determine what the block height is.

So the block height of that block you reference there is actually 0x0000daab (or 55979 in decimal).

The ref_block_num field of a transaction is the height of the reference block (modulo 2^16).
So in this case it would again be 55979.

The ref_block_prefix field of a transaction is some 32-bits of the reference block ID
(other than the first 4 bytes which represents the height and therefore serves no meaningful
validation purposes) as a simple check to ensure you are referencing the actual block you meant
to reference and not some other block on another fork that has the same block height.

Those are taken from the 2nd 64-bit word of the block ID which is then cast to
uint32_t so it is the least significant 32-bits of the 2nd 64-bit word.

So the 2nd 64-bit word would be taken from the sequence of bytes
(represented in hex): 0x23, 0x59, 0xde, 0xf6, 0x03, 0x3b, 0x04, 0x63.
When pulled as a uint64_t number on a little endian machine, that is the number 0x63043b03f6de5923.
And the least significant 32-bits of that number is 0xf6de5923 which is what ref_block_prefix
should be.

The ref_block_num would be 0x0000daab mod 2^16 which is 0xdaab.

expiration has a max of now + 3600 seconds.
delay_sec should be 0 for normal things. (it's used in deferred txn's which aren't really used).
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionIn {
    #[serde(with = "eosio_datetime_format")]
    pub expiration: DateTime<Utc>,
    pub ref_block_num: u16,
    pub ref_block_prefix: u32,
    pub max_net_usage_words: u32,
    pub max_cpu_usage_ms: u8,
    pub delay_sec: u32,
    pub context_free_actions: Vec<String>,
    pub actions: Vec<ActionIn>,
    pub transaction_extensions: Vec<String>,
}

impl TransactionIn {
    pub fn dummy() -> TransactionIn {
        TransactionIn {
            transaction_extensions: vec![],
            ref_block_num: 0,
            max_net_usage_words: 0,
            expiration: Utc::now() + Duration::days(1),
            delay_sec: 0,
            max_cpu_usage_ms: 0,
            actions: vec![],
            ref_block_prefix: 0,
            context_free_actions: vec![],
        }
    }
    pub fn simple(
        actions: Vec<ActionIn>,
        ref_block_id: &str,
        expiration: DateTime<Utc>,
    ) -> Result<TransactionIn> {
        let hash = TransactionIn::block_to_hash(ref_block_id)?;

        let ref_block_num: u16 = (((hash[0] >> 32) & 0xffff_ffff) as u16).to_le();
        let ref_block_prefix: u32 = ((hash[1] >> 32 & 0xffff_ffff) as u32).to_be();

        Ok(TransactionIn {
            transaction_extensions: vec![],
            ref_block_num,
            max_net_usage_words: 0,
            expiration,
            delay_sec: 0,
            max_cpu_usage_ms: 0,
            actions,
            ref_block_prefix,
            context_free_actions: vec![],
        })
    }

    pub fn hex_to_u64(hex: &str) -> u64 {
        let mut val: u64 = 0;
        for char in hex.bytes() {
            let digit = if char >= b'a' {
                char + 10 - b'a'
            } else {
                char - b'0'
            };
            val = (val << 4) + digit as u64;
        }
        val
    }
    pub fn block_to_hash(ref_block_id: &str) -> Result<Vec<u64>> {
        if ref_block_id.len() != 64 {
            Err("Invalid ref_block id. expecting len of 64".into())
        } else {
            let v: Vec<u64> = vec![
                TransactionIn::hex_to_u64(&ref_block_id[0..16]),
                TransactionIn::hex_to_u64(&ref_block_id[16..32]),
                TransactionIn::hex_to_u64(&ref_block_id[33..48]),
                TransactionIn::hex_to_u64(&ref_block_id[49..64]),
            ];
            Ok(v)
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorDetails {
    pub message: String,
    pub file: String,
    pub line_number: usize,
    pub method: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorInt {
    pub code: usize,
    pub name: String,
    pub what: String,
    pub details: Vec<ErrorDetails>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorReply {
    pub code: usize,
    pub message: String,
    pub error: ErrorInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackedTransactionIn {
    pub signatures: Vec<String>,
    pub compression: String,
    pub packed_context_free_data: String,
    pub packed_trx: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetRawABI {
    pub account_name: String,
    pub code_hash: String,
    pub abi_hash: String,
    pub abi: String,
}

impl GetRawABI {
    /*
    EOSIO doesn't seem to pad base64 correctly
    see https://github.com/EOSIO/eos/issues/8161
     */
    fn fix_padding(str: &str) -> String {
        let mut bare: String = str.replacen('=', "", 4);
        let len = bare.len();
        let to_len = len + (4 - (len % 4));
        for _i in len..to_len {
            bare.push('=');
        }
        bare
    }

    pub fn decode_abi(&self) -> Result<Vec<u8>> {
        let fixed = GetRawABI::fix_padding(&self.abi);
        Ok(base64::decode(fixed)?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionSetcodeData {
    pub(crate) account: String,
    pub(crate) vmtype: u8,
    pub(crate) vmversion: u8,
    pub(crate) code: String,
}

impl ActionSetcodeData {
    pub fn to_hex(&self, abieos: &ABIEOS) -> Result<String> {
        // abieos NEEDS the json to be in a specific order serde_json doesn't do that
        let json = format!(
            "{{ \"account\":\"{}\", \"vmtype\":{},\"vmversion\":{},\"code\":\"{}\" }}",
            self.account, self.vmtype, self.vmversion, self.code
        );

        let hex = abieos.json_to_hex("eosio", "setcode", &json)?;
        Ok(String::from(hex))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionSetData {
    pub(crate) account: String,
    pub(crate) abi: String,
}

impl ActionSetData {
    pub fn to_hex(&self, abieos: &ABIEOS) -> Result<String> {
        let json = format!(
            "{{ \"account\":\"{}\", \"abi\":\"{}\"}}",
            self.account, self.abi
        );

        let hex = abieos.json_to_hex("eosio", "setabi", &json);
        Ok(String::from(hex?))
    }
}

#[derive(Debug, Deserialize)]
pub struct TransactionResponse {
    pub processed: TransactionProcessedResponse,
    pub transaction_id: String,
}

#[derive(Debug, Deserialize)]
pub struct TransactionReceipt {
    pub cpu_usage_us: usize,
    pub net_usage_words: usize,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountRamDelta {
    pub account: String,
    pub delta: isize,
}

#[derive(Debug, Deserialize)]
pub struct ActionReceipt {
    pub receiver: String,
    pub abi_sequence: usize,
    pub recv_sequence: usize,
    // auth_sequence: Vec< String|usize>
    pub code_sequence: usize,
    pub global_sequence: usize,
    pub act_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ActionACTData {
    ActionACTDataSetCode {
        code: Option<String>,
        vmtype: usize,
        account: String,
        vmversion: usize,
    },
    String,
    /*
    ActionACTDataSetABI {
        account: String,
        abi: String,
    }*/
}

#[derive(Debug, Deserialize)]
pub struct ActionACT {
    pub authorization: Vec<Permission>,
    pub name: String,

    //  #[serde(with = "eosio_action_trace")]
    // data: HashMap<String,Value>,
    pub account: String,
    pub hex_data: String,
}

#[derive(Debug, Deserialize)]
pub struct ActionTrace {
    pub account_ram_deltas: Vec<AccountRamDelta>,
    pub console: Option<String>,
    pub action_ordinal: isize,
    // inline_traces:[],
    pub receipt: ActionReceipt,
    pub act: ActionACT,
    pub context_free: bool,
    pub producer_block_id: Option<String>,
    pub except: Option<String>,
    pub trx_id: String,
    pub block_num: usize,
    pub error_code: Option<String>,
    #[serde(with = "eosio_datetime_format")]
    pub block_time: DateTime<Utc>,
    pub closest_unnotified_ancestor_action_ordinal: usize,
    pub elapsed: usize,
    pub receiver: String,
    //account_disk_deltas : [],
    pub return_value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TransactionProcessedResponse {
    pub scheduled: bool,
    pub error_code: Option<String>,
    pub action_traces: Vec<ActionTrace>,
    pub block_num: usize,
    pub producer_block_id: Option<String>,
    pub except: Option<String>,
    pub receipt: TransactionReceipt,
    pub id: String,
    pub elapsed: usize,
    pub net_usage: usize,
    #[serde(with = "eosio_datetime_format")]
    pub block_time: DateTime<Utc>,
    pub account_ram_delta: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockTransactionAction {
    pub account: String,
    pub name: String,
    pub authorization: Vec<AuthorizationIn>,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockTransaction {
    #[serde(with = "eosio_datetime_format")]
    pub expiration: DateTime<Utc>,
    pub ref_block_num: u16,
    pub ref_block_prefix: u32,
    pub max_net_usage_words: u32,
    pub max_cpu_usage_ms: u8,
    pub delay_sec: u32,
    pub context_free_actions: Vec<String>,
    pub actions: Vec<BlockTransactionAction>,
}

#[derive(Debug, Deserialize)]
pub struct BlockTransactionTrx {
    pub id: String,
    signatures: Vec<String>,
    compression: String,
    packed_context_free_data: String,
    // context_free_data: Vec<?>
    packed_trx: String,
    pub transaction: BlockTransaction,
}

#[derive(Debug, Deserialize)]
pub struct BlockTransactions {
    pub status: String,
    pub cpu_usage_us: usize,
    pub net_usage_words: usize,
    pub trx: BlockTransactionTrx,
}

#[derive(Debug, Deserialize)]
pub struct GetBlock {
    #[serde(with = "eosio_datetime_format")]
    pub timestamp: DateTime<Utc>,
    pub producer: String,
    pub confirmed: usize,
    pub previous: String,
    pub transaction_mroot: String,
    pub action_mroot: String,
    pub schedule_version: usize,
    pub new_producers: Option<String>,
    pub producer_signature: String,
    pub transactions: Vec<BlockTransactions>,
    pub id: String,
    pub block_num: usize,
    pub ref_block_prefix: usize,
}

#[derive(Debug, Deserialize)]
pub struct TableRow {
    pub code: String,
    pub scope: String,
    pub table: String,
    pub payer: String,
    pub count: usize,
}

#[derive(Debug, Deserialize)]
pub struct GetTableByScope {
    pub rows: Vec<TableRow>,
    pub more: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetTableByScopeIn {
    pub code: String,
    pub table: String,
    pub lower_bound: String,
    pub upper_bound: String,
    pub limit: usize,
    pub reverse: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetTableRowsIn {
    pub json: bool,
    /// set this to false if you are using GetTableRow
    pub code: String,
    pub scope: String,
    pub table: String,
    pub table_key: String,
    pub lower_bound: String,
    pub upper_bound: String,
    pub limit: usize,
    pub key_type: String,
    pub index_position: String,
    pub encode_type: String,
    pub reverse: bool,
    pub show_payer: bool,
}
#[derive(Debug, Deserialize)]
pub struct GetTableRow {
    pub data: String,
    /// set to json:false in request, returns abieos-packed version
    pub payer: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct GetTableRows {
    pub rows: Vec<GetTableRow>,
    pub more: bool,
    pub next_key: String,
}
