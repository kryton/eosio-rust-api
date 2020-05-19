use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};

pub(crate) mod eosio_datetime_format {
    use chrono::{DateTime, Utc, TimeZone, NaiveDateTime};
    use serde::{self, Deserialize, Serializer, Deserializer};

    const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S";

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
        let slice_len = if s.contains(".") {
            len.checked_sub(4).unwrap_or(0)
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
    last_irreversible_block_num: usize,
    last_irreversible_block_id: String,
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
    pub permission: String,
    pub actor: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct GetCodeHash {
    pub account_name: String,
    pub hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionIn {
    pub account: String,
    pub data: String,
    pub authorization: Vec<AuthorizationIn>,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionIn {
    transaction_extensions: Vec<String>,
    ref_block_num: usize,
    max_net_usage_words: usize,
    #[serde(with = "eosio_datetime_format")]
    expiration: DateTime<Utc>,
    delay_sec: usize,
    max_cpu_usage_ms: usize,
    pub actions: Vec<ActionIn>,
    ref_block_prefix: usize,
    context_free_actions: Vec<String>,
    pub signatures: Vec<String>, // KleosD 2.1 returns signatures here
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
            signatures: vec![],
        }
    }
    pub fn simple(action: ActionIn, ref_block_num: usize, ref_block_prefix: usize, expiration: DateTime<Utc>) -> TransactionIn {
        TransactionIn {
            transaction_extensions: vec![],
            ref_block_num,
            max_net_usage_words: 0,
            expiration,
            delay_sec: 0,
            max_cpu_usage_ms: 0,
            actions: vec![action],
            ref_block_prefix,
            context_free_actions: vec![],
            signatures: vec![]
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
