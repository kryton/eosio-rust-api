use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use crate::errors::{Result};

pub(crate) mod eosio_datetime_format {
    use chrono::{DateTime, Utc, TimeZone, NaiveDateTime};
    use serde::{self, Deserialize, Serializer, Deserializer};

    const FORMAT: &str = "%Y-%m-%dT%H:%M:%S";

    // The signature of a serialize_with function must follow the pattern:
    //
    //    fn serialize<S>(&T, S) -> Result<S::Ok, S::Error>
    //    where
    //        S: Serializer
    //
    // although it may also be generic over the input types T.
    pub fn serialize<S>(
        date: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
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
    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error>
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceLimit {
    max: isize,
    available: isize,
    used: isize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Key {
    key: String,
    weight: isize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Permission {
    permission: String,
    actor: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    weight: isize,
    permission: Permission,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequiredAuth {
    waits: Vec<String>,
    threshold: isize,
    accounts: Vec<Account>,
    keys: Vec<Key>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Permissions {
    parent: String,
    perm_name: String,
    required_auth: RequiredAuth,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VoterInfo {
    producers: Vec<String>,
    is_proxy: isize,
    owner: String,
    // staked: usize, Wax holds this as a string, EOS is a usize
    proxy: String,
    flags1: isize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetAccount {
    account_name: String,
    head_block_num: usize,
    privileged: bool,
    #[serde(with = "eosio_datetime_format")]
    last_code_update: DateTime<Utc>,
    #[serde(with = "eosio_datetime_format")]
    head_block_time: DateTime<Utc>,
    #[serde(with = "eosio_datetime_format")]
    created: DateTime<Utc>,
    core_liquid_balance: Option<String>,
    ram_quota: isize,
    net_weight: isize,
    cpu_weight: isize,
    ram_usage: usize,
    cpu_limit: ResourceLimit,
    net_limit: ResourceLimit,
    voter_info: Option<VoterInfo>,
    refund_request: Option<String>,
    permissions: Vec<Permissions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiTypes {
    new_type_name: String,
    #[serde(rename = "type")]
    abi_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiField {
    name: String,
    #[serde(rename = "type")]
    abi_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiStruct {
    name: String,
    base: String,
    fields: Vec<AbiField>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiAction {
    name: String,
    #[serde(rename = "type")]
    abi_type: String,
    ricardian_contract: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiTable {
    name: String,
    #[serde(rename = "type")]
    abi_type: String,
    index_type: String,
    key_names: Vec<String>,
    key_types: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiRicardianClauses {
    id: String,
    body: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiErrorMessages {
    error_code: String,
    error_msg: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiExtensions {
    tag: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AbiVariants {
    name: String,
    typea: Vec<String>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Abi {
    version: String,
    types: Vec<AbiTypes>,
    structs: Vec<AbiStruct>,
    actions: Vec<AbiAction>,
    tables: Vec<AbiTable>,
    ricardian_clauses: Vec<AbiRicardianClauses>,
    error_messages: Vec<AbiErrorMessages>,
    abi_extensions: Vec<AbiExtensions>,
    variants: Vec<AbiVariants>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetAbi {
    account_name: String,
    abi: Abi,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequiredKeys {
    pub required_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetInfo {
    server_version: String,
    chain_id: String,
    pub head_block_num: usize,
    pub last_irreversible_block_num: usize,
    pub last_irreversible_block_id: String,
    head_block_id: String,
    #[serde(with = "eosio_datetime_format")]
    pub head_block_time: DateTime<Utc>,
    head_block_producer: String,
    virtual_block_cpu_limit: usize,
    virtual_block_net_limit: usize,
    block_cpu_limit: usize,
    block_net_limit: usize,
    server_version_string: String,
    fork_db_head_block_num: usize,
    fork_db_head_block_id: String,
    server_full_version_string: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationIn {
    pub actor: String,
    pub permission: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct GetCodeHash {
    pub account_name: String,
    pub hash: String,
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
    expiration: DateTime<Utc>,
    ref_block_num: u16,
    ref_block_prefix: u32,
    max_net_usage_words: u32,
    max_cpu_usage_ms: u8,
    delay_sec: u32,
    context_free_actions: Vec<String>,
    pub actions: Vec<ActionIn>,
    transaction_extensions: Vec<String>,
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
    expiration: DateTime<Utc>,
    ref_block_num: u16,
    ref_block_prefix: u32,
    max_net_usage_words: u32,
    max_cpu_usage_ms: u8,
    delay_sec: u32,
    context_free_actions: Vec<String>,
    pub actions: Vec<ActionIn>,
    transaction_extensions: Vec<String>,
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
    pub fn simple(action: ActionIn, ref_block_id:&str, expiration: DateTime<Utc>) -> Result<TransactionIn> {
     //  let dummy="0000daabcc9912b62359def6033b0463d3a605c0ba7d6c779452ed321649db15";
        let hash = TransactionIn::block_to_hash(ref_block_id)?;

        let ref_block_num:u16 =   (((hash[0] >> 32 ) & 0xffff_ffff) as u16).to_le();
        let ref_block_prefix:u32= ((hash[1]>>32 & 0xffff_ffff) as u32).to_be();

        Ok(TransactionIn {
            transaction_extensions: vec![],
            ref_block_num:ref_block_num,
            max_net_usage_words: 0,
            expiration,
            delay_sec: 0,
            max_cpu_usage_ms: 0,
            actions: vec![action],
            ref_block_prefix ,
            context_free_actions: vec![],
        })
    }

    pub fn hex_to_u64(hex:&str) -> u64 {
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
            let v: Vec<u64> = vec![TransactionIn::hex_to_u64(&ref_block_id[0..16]),
                                   TransactionIn::hex_to_u64(&ref_block_id[16..32]),
                                   TransactionIn::hex_to_u64(&ref_block_id[33..48]),
                                   TransactionIn::hex_to_u64(&ref_block_id[49..64])];
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
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    processed: TransactionProcessedResponse,
    transaction_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionReceipt {
cpu_usage_us: usize,
net_usage_words : usize,
status : String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountRamDelta {
    account: String,
    delta: isize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionReceipt {
    receiver:String,
    abi_sequence:usize,
    recv_sequence:usize,
    // auth_sequence: Vec< String|usize>
    code_sequence:usize,
    global_sequence:usize,
    act_digest:String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionACTData {
    code:Option<String>,
    vmtype: usize,
    account: String,
    vmversion: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionACT {
    authorization: Vec<Permission>,
    name: String,
    data: ActionACTData,
    account: String,
    hex_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionTrace {
    account_ram_deltas: Vec<AccountRamDelta>,
    console: Option<String>,
    action_ordinal: isize,
    // inline_traces:[],
    receipt: ActionReceipt,
    act: ActionACT,
    context_free: bool,
    producer_block_id: Option<String>,
    except: Option<String>,
    trx_id: String,
    block_num: usize,
    error_code: Option<String>,
    #[serde(with = "eosio_datetime_format")]
    block_time: DateTime<Utc>,
    closest_unnotified_ancestor_action_ordinal: usize,
    elapsed: usize,
    receiver: String,
    //account_disk_deltas : [],
    return_value: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionProcessedResponse {
    scheduled:bool,
    error_code:Option<String>,
    action_traces: Vec<ActionTrace>,
    block_num:usize,
    producer_block_id:Option<String>,
    except:Option <String>,
    receipt: TransactionReceipt,
    id: String,
    elapsed: usize,
    net_usage: usize,
    #[serde(with = "eosio_datetime_format")]
    block_time: DateTime<Utc>,
    account_ram_delta: Option<String>,
}
