lazy_static! {
    static ref BASE64_MAP: [i32; 256] = create_base64_map();
    static ref BASE58_MAP: [i32; 256] = create_base58_map();
}

use ripemd160::{Digest, Ripemd160};

//TODO use uint.
// use uint::construct_uint;

/**
 * @module Numeric
 */
// copyright defined in eosjs/LICENSE.txt


const BASE58CHARS: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE64CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


pub fn create_base58_map() -> [i32; 256] {
    let mut base58_mapi: [i32; 256] = [-1; 256];
    let mut i = 1;
    BASE58CHARS.chars().for_each(|c| {
        base58_mapi[c as usize] = i;
        i += 1;
    });
    return base58_mapi;
}

pub fn create_base64_map() -> [i32; 256] {
    let mut base64_mapi: [i32; 256] = [-1; 256];
    let mut i = 1;
    BASE64CHARS.chars().for_each(|c| {
        base64_mapi[c as usize] = i;
        i += 1;
    });
    base64_mapi['=' as usize] = 0;

    return base64_mapi;
}

/** Is `bignum` a negative number? */
pub fn is_negative(bignum: &Vec<u8>) -> bool {
    let last_digit = bignum[bignum.len() - 1];
    return (last_digit & 0x80) != 0;
}

/** Negate `bignum` */
pub fn negate(bignum: &Vec<u8>) -> Vec<u8> {
    let mut carry = 1;
    let mut result: Vec<u8> = Vec::with_capacity(bignum.len());
    for part in bignum {
        let x = (!part & 0xff) + carry;
        result.push(x);
        carry = x.checked_shr(8).unwrap_or(0);
    }
    return result;
}

/**
 * Convert an unsigned decimal number in `s` to a bignum
 * @param size bignum size (bytes)
 */

pub fn decimal_to_binary(size: usize, s: &str) -> Vec<u8> {
    let mut result: Vec<u8> = vec![0; size];

    s.chars().for_each(|c| {
        if !c.is_digit(10) {
            panic!("String contains non-decimals");
        } else {
            let mut carry: u16 = c as u16 - '0' as u16;

            for j in 0..size {
                let x: u16 = (result[j] as u16) * 10 + carry;
                result[j] = (x & 0xffff) as u8;
                carry = x.checked_shr(8).unwrap_or(0);
            }
            if carry != 0 {
                panic!("number is out of range")
            }
        }
    });

    return result;
}

/**
 * Convert a signed decimal number in `s` to a bignum
 * @param size bignum size (bytes)
 */
pub fn signed_decimal_to_binary(size: usize, s: &str) -> Vec<u8> {
    if s.len() <= 0 {
        return decimal_to_binary(size, "0");
    }

    let is_neg: bool = s.chars().next().unwrap_or('0') == '-';
    if is_neg {
        let result = negate(&decimal_to_binary(size, &s[1..]));
        if is_negative(&result) {
            return result;
        } else {
            panic!("Invalid number? should be negative");
        }
    } else {
        let result = decimal_to_binary(size, s);
        if is_negative(&result) {
            panic!("number overflow: should be positive");
        } else {
            return result;
        }
    }
}

/**
 * Convert `bignum` to an unsigned decimal number
 * @param minDigits 0-pad result to this many digits
 */
pub fn binary_to_decimal(bignum: &Vec<u8>, min_digits: usize) -> String {
    let mut result: Vec<char> = std::iter::repeat('0').take(min_digits).collect();

    for i in (0..bignum.len()).rev() {
        let mut carry = bignum[i];

        for j in 0..result.len() {
            let mut x: u16 = (result[j] as u16 - '0' as u16).checked_shl(8).unwrap_or(0);
            x += carry as u16;
            result[j] = (('0' as u8) + (x % 10) as u8) as char;
            carry = (x / 10) as u8 | 0;
        }
        while carry > 0 {
            result.push(('0' as u8 + carry % 10) as char);
            carry = (carry / 10) | 0;
        }
    }
    result.reverse();
    result.into_iter().collect::<String>()
}

/**
 * Convert `bignum` to a signed decimal number
 * @param minDigits 0-pad result to this many digits
 */
pub fn signed_binary_to_decimal(bignum: &Vec<u8>, min_digits: usize) -> String {
    return if is_negative(bignum) {
        "-".to_owned() + binary_to_decimal(&negate(bignum), min_digits).as_str()
    } else {
        binary_to_decimal(&bignum, min_digits)
    };
}

/**
 * Convert an unsigned base-58 number in `s` to a bignum
 * @param size bignum size (bytes)
 */

pub fn base58_to_binary(_size: usize, s: &str) -> Vec<u8> {
    match bs58::decode(s).into_vec() {
        Ok(vec) => return vec,
        Err(err) => panic!("{}", err),
    }
}

pub fn binary_to_base58(bignum: Vec<u8>, _min_digits: usize) -> String {
    bs58::encode(bignum).into_string()
}

/**
 * Convert an unsigned base-64 number in `s` to a bignum
 */
pub fn base64_to_binary(s: &str) -> Vec<u8> {
    match base64::decode(s) {
        Ok(vec) => return vec,
        Err(err) => panic!("{}", err),
    }
}

pub fn binary_to_base64(bignum: &Vec<u8>) -> String {
    base64::encode(bignum)
}

pub fn digest_suffix_ripemd160(data: &Vec<u8>, suffix: &str) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    //hasher.input(data);
    let vec: Vec<u8> = suffix.chars().map(|c| c as u8).collect();
    let combined = [&data[..], &vec[..]].concat();
    hasher.input(combined);
    hasher.result().to_vec()
}

fn ripemd160(data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.input(data);
    hasher.result().to_vec()
}

fn is_invalid_digest(block1: Vec<u8>, block2: Vec<u8>, offset: usize) -> bool {
    return block1[0] != block2[offset + 0]
        || block1[1] != block2[offset + 1]
        || block1[2] != block2[offset + 2]
        || block1[3] != block2[offset + 3];
}
/*
/** Key types this library supports */
#[derive(PartialEq)]
pub enum KeyType {
    K1 = 0,
    R1 = 1,
}


/** Public key data size, excluding type field */
pub const PUBLIC_KEY_DATA_SIZE: usize = 33;

/** Private key data size, excluding type field */
pub const PRIVATE_KEY_DATA_SIZE: usize = 32;

/** Private key data size, excluding type field */
pub const SIGNATURE_DATA_SIZE: usize = 65;

/** Public key, private key, or signature in binary form */
pub struct Key {
    key_type: KeyType,
    data: Vec<u8>,
}

fn string_to_key(
    s: &str,
    key_type: KeyType,
    size: usize,
    suffix: &str,
) -> Result<Key, EOSIONumericError> {
    let whole = base58_to_binary(size + 4, s);
    let mut result_data = vec![];
    for i in 0..size {
        result_data.push(whole[i]);
    }
    let result: Key = Key {
        key_type,
        data: result_data,
    };
    let digest = digest_suffix_ripemd160(&result.data, suffix);
    if is_invalid_digest(digest, whole, size) {
        return Err(InvalidChecksum);
    }
    return Ok(result);
}

fn key_to_string(key: &Key, suffix: &str, prefix: &str) -> String {
    let digest = digest_suffix_ripemd160(&key.data, suffix);
    let mut whole: Vec<u8> = Vec::with_capacity(key.data.len() + 4);
    for i in 0..key.data.len() {
        whole[i] = key.data[i];
    }
    for i in 0..4 {
        whole[i + key.data.len()] = digest[i];
    }
    let b58 = binary_to_base58(whole, key.data.len() + 4);

    return format!("{}{}", prefix, b58);
}

 */
/*
/** Convert key in `s` to binary form */
pub fn string_to_publickey(s: &str) -> Result<Key, EOSIONumericError> {
    match &s[..3] {
        "EOS" => {
            let whole = base58_to_binary(PUBLIC_KEY_DATA_SIZE + 4, &s[3..]);
            let mut data: Vec<u8> = Vec::with_capacity(PUBLIC_KEY_DATA_SIZE);
            for i in 0..PUBLIC_KEY_DATA_SIZE {
                data.push(whole[i]);
            }
            let digest = ripemd160(&data);

            if is_invalid_digest(digest, whole, PUBLIC_KEY_DATA_SIZE) {
                return Err(EOSIONumericError::InvalidChecksum);
            }
            Ok(Key { key_type: K1, data })
        }
        "PUB" => match &s[3..7] {
            "_K1_" => string_to_key(&s[7..], KeyType::K1, PUBLIC_KEY_DATA_SIZE, "K1"),
            "_R1_" => string_to_key(&s[7..], KeyType::R1, PUBLIC_KEY_DATA_SIZE, "R1"),
            _ => Err(InvalidPublicKey),
        },
        _ => Err(InvalidPublicKey),
    }
}

/** Convert `key` to string (base-58) form */
pub fn publickey_to_string(key: &Key) -> Result<String, EOSIONumericError> {
    match key.key_type {
        K1 => Ok(key_to_string(key, "K1", "PUB_K1_")),
        R1 => Ok(key_to_string(key, "R1", "PUB_R1_")),
    }
}

/**
 * If a key is in the legacy format (`EOS` prefix), then convert it to the new format (`PUB_K1_`).
 * Leaves other formats untouched
 */
pub fn convert_legacy_publickey(s: &str) -> Result<String, EOSIONumericError> {
    match &s[0..3] {
        "EOS" => match string_to_publickey(s) {
            Ok(key) => publickey_to_string(&key),
            Err(e) => Err(e),
        },
        _ => Ok(String::from(s)),
    }
}
/** If a key is in the legacy format (`EOS` prefix), then convert it to the new format (`PUB_K1_`).
 * Leaves other formats untouched
 */
pub fn convert_legacy_publickeys(strings: Vec<&str>) -> Result<Vec<String>, EOSIONumericError> {
    let results: Vec<Result<String, EOSIONumericError>> = strings
        .iter()
        .map(|s| convert_legacy_publickey(s))
        .collect();
    let err = results.iter().find(|f| f.is_err());

    if err.is_some() {
        return Err(InvalidKeyFormat);
    }

    let mut part1: Vec<String> = Vec::with_capacity(results.len());

    for x in results {
        match x {
            Err(_) => {}
            Ok(s) => part1.push(s),
        }
    }

    Ok(part1)
}

 */
/*
/** Convert key in `s` to binary form */
pub fn string_to_private_key(s: &str) -> Result<Key, EOSIONumericError> {
    match &s[..7] {
        "PVT_R1_" => string_to_key(&s[7..], R1, PRIVATE_KEY_DATA_SIZE, "R1"),
        _ => Err(InvalidPrivateKey),
    }
}
/** Convert `key` to string (base-58) form */
pub fn private_key_to_string(key: &Key) -> Result<String, EOSIONumericError> {
    match key.key_type {
        R1 => Ok(key_to_string(key, "R1", "PVT_R1_")),
        _ => Err(InvalidPrivateKey),
    }
}

/** Convert key in `s` to binary form */
pub fn string_to_signature(s: &str) -> Result<Key, EOSIONumericError> {
    match &s[..7] {
        "SIG_K1_" => string_to_key(&s[..7], K1, SIGNATURE_DATA_SIZE, "K1"),
        "SIG_R1_" => string_to_key(&s[..7], R1, SIGNATURE_DATA_SIZE, "R1"),
        _ => Err(InvalidSignature),
    }
}
/** Convert `signature` to string (base-58) form */
pub fn signature_to_string(sig: &Key) -> Result<String, EOSIONumericError> {
    match sig.key_type {
        K1 => Ok(key_to_string(sig, "K1", "SIG_K1_")),
        R1 => Ok(key_to_string(sig, "R1", "SIG_R1_")),
        //_ => Err(InvalidSignature),
    }
}

*/

#[cfg(test)]
mod tests {
    use super::*;
   // use crate::numeric::KeyType::{K1, R1};

    #[test]
    fn base58_mapping() {
        assert_eq!(BASE58_MAP[12], -1);
        assert_eq!(BASE58_MAP['2' as usize], 2);
        assert_eq!(BASE58_MAP['A' as usize], 10);
    }

    #[test]
    fn base64_mapping() {
        assert_eq!(BASE64_MAP[12], -1);
        assert_eq!(BASE64_MAP['A' as usize], 1);
        assert_eq!(BASE64_MAP['2' as usize], 55);
        assert_eq!(BASE64_MAP['=' as usize], 0);
    }

    #[test]
    fn base58_to_binary_test() {
        let str = "8";
        let bin = base58_to_binary(str.len(), str);
        assert_eq!(bin[0], 7);
        let str2 = "5imfbmmHC83VRxLRTcvovviAc6LPpyszcDuKtkwka9e9Jg37Hp";
        //let _result2="026da0e4d65a933e828c9de388005281dfa7e4948895d10c7c3ef617b5e40d97fde8cbd887";
        let bin2 = base58_to_binary(str2.len(), str2);
        assert_eq!(bin2.len(), 37);
        assert_eq!(bin2[0], 2);
        assert_eq!(bin2[36], 0x87);
    }

    #[test]
    fn base64_to_binary_test() {
        let str = "TVqQ";
        let bin = base64_to_binary(str);

        assert_eq!(bin, vec![0x4D, 0x5a, 0x90]);
        let str2 = "tsU=";

        let bin2 = base64_to_binary(str2);
        assert_eq!(bin2, vec![0xb6, 0xc5]);
    }

    #[test]
    fn binary_to_base58_test() {
        let bignum: Vec<u8> = vec![7];
        let str = binary_to_base58(bignum, 1);
        assert_eq!(str, "8");

        // test to make sure we can go back and forth
        let str2 = "5imfbmmHC83VRxLRTcvovviAc6LPpyszcDuKtkwka9e9Jg37Hp";
        let bin2 = base58_to_binary(str2.len(), str2);
        assert_eq!(binary_to_base58(bin2, 1), str2);

        let bignum3: Vec<u8> = vec![
            0x03, 0xf0, 0x39, 0xfd, 0xcd, 0xb7, 0x28, 0xef, 0xbb, 0xdd, 0xf4, 0xee, 0x45, 0x24,
            0x19, 0xa9, 0x88, 0x49, 0x7d, 0xeb, 0xb7, 0xbd, 0x1b, 0x42, 0x64, 0x4c, 0x5f, 0xa6,
            0x6e, 0x9a, 0xf8, 0xc8, 0xb6, 0xc6, 0x0a, 0x20, 0xd4,
        ];
        let str = binary_to_base58(bignum3, 1);
        assert_eq!(str, "8f2o2LLQ3phteqyazxirQZnQzQFpnjLnXiUFEJcsSYhnjWNvSX");
    }

    #[test]
    fn negate_test() {
        let bignum: Vec<u8> = vec![0x3, 0x4];

        let b2 = negate(&bignum);
        assert!(is_negative(&b2));
        let result = negate(&b2);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], bignum[0]);
        assert_eq!(result[1], bignum[1]);
    }

    #[test]
    fn decimal_to_binary_test() {
        let s = "12345";
        let bignum = decimal_to_binary(8, s);
        assert_eq!(bignum.len(), 8);
        assert_eq!(bignum[0], 0x39);
        assert_eq!(bignum[1], 0x30);
        assert_eq!(bignum[2], 0x0);
    }

    #[test]
    fn signed_decimal_to_binary_test() {
        let s = "12345";
        assert_eq!(signed_decimal_to_binary(8, s), decimal_to_binary(8, s));
        let bignum = signed_decimal_to_binary(8, "-12345");
        assert!(is_negative(&bignum));
        assert_eq!(negate(&bignum), decimal_to_binary(8, s));
    }

    #[test]
    fn binary_to_decimal_test() {
        //let s = "12345";
        //let bignum2 = decimal_to_binary(8, s);
        let bignum = vec![0x39, 0x30, 0];
        let str = binary_to_decimal(&bignum, 3);
        assert_eq!("12345", str);
        assert_eq!("00012345", binary_to_decimal(&bignum, 8));
    }

    #[test]
    fn signed_binary_to_decimal_test() {
        let bignum = signed_decimal_to_binary(2, "-12345");
        assert_eq!("-12345", signed_binary_to_decimal(&bignum, 2));
        assert_eq!("-00012345", signed_binary_to_decimal(&bignum, 8));
        let bignum2 = decimal_to_binary(8, "12345");
        assert_eq!("00012345", signed_binary_to_decimal(&bignum2, 8));
    }

    #[test]
    fn digest_suffix_ripemd160_test() {
        let bignum: Vec<u8> = vec![0x49, 0x61, 0x6e];
        let suffix = "-Kry";
        let digest_act = vec![
            0xbe, 0x64, 0x6f, 0x38, 0x8a, 0xf0, 0x5e, 0x6e, 0xaa, 0x4b, 0xcd, 0x0f, 0xaa, 0xcb,
            0x2a, 0x1d, 0x68, 0x58, 0x43, 0x51,
        ];
        let digest = digest_suffix_ripemd160(&bignum, suffix);
        assert_eq!(digest, digest_act);
    }

    /*

    #[test]
    fn string_to_key_test() {
        let _pubkey_k1 = "PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX";
        let _pubkey_r1 = "PUB_R1_6FPFZqw5ahYrR9jD96yDbbDNTdKtNqRbze6oTDLntrsANgQKZu";
        match string_to_key(
            "859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX",
            K1,
            PUBLIC_KEY_DATA_SIZE,
            "K1",
        ) {
            Err(err) => assert!(false),
            Ok(key) => assert!(true),
        }

        match string_to_key(
            "6FPFZqw5ahYrR9jD96yDbbDNTdKtNqRbze6oTDLntrsANgQKZu",
            R1,
            PUBLIC_KEY_DATA_SIZE,
            "R1",
        ) {
            Err(err) => assert!(false),
            Ok(key) => assert!(true),
        }
        match string_to_key(
            "6FPFZqw5ahYrR9jD96yDbbDNTdKtNqRbze6oTDLntrsANgQKZu",
            R1,
            PUBLIC_KEY_DATA_SIZE,
            "K1",
        ) {
            Err(err) => assert!(true),
            Ok(key) => assert!(false),
        }
    }

     */
/*
    #[test]
    fn string_to_publickey_test() {
        let pubkey_k1 = "PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX";
        let pubkey_r1 = "PUB_R1_6FPFZqw5ahYrR9jD96yDbbDNTdKtNqRbze6oTDLntrsANgQKZu";
        let pubkey_eos = "EOS67SCWnz6trqFPCtmxfjYEPSsT9JKRn4zhow8X3VTtgaEzNMULF";
        let pubkey_invalid = "PUB_WW_67SCWnz6trqFPCtmxfjYEPSsT9JKRn4zhow8X3VTtgaEzNMULF";
        let pubkey_invalid2 = "EKS67SCWnz6trqFPCtmxfjYEPSsT9JKRn4zhow8X3VTtgaEzNMULF";
        /*
           "PUB_R1_8S4TodyXa9KASMAJgkLbstFYzAWHNjNJPhpHuqqHF9Af8ekV7i",
           "PVT_R1_2sPCnkH6652KFYQZNWuQvgfTTHvqjrhV6pQ8tcVQGqBNsopKZp"
            "EOS67SCWnz6trqFPCtmxfjYEPSsT9JKRn4zhow8X3VTtgaEzNMULF",
           "5JaKaxySEyjBFGT9K9cYKSFhfojn1RfPcresqRVbmtxnQt1w3qW"
        */

        match string_to_publickey(pubkey_k1) {
            Err(err) => assert!(false),
            Ok(key) => assert!(key.key_type == KeyType::K1),
        }
        match string_to_publickey(pubkey_r1) {
            Err(err) => assert!(false),
            Ok(key) => assert!(key.key_type == KeyType::R1),
        }
        match string_to_publickey(pubkey_eos) {
            Err(err) => assert!(false),
            Ok(key) => assert!(key.key_type == KeyType::K1),
        }
        match string_to_publickey(pubkey_invalid) {
            Err(err) => assert!(true),
            Ok(key) => assert!(false),
        }
        match string_to_publickey(pubkey_invalid2) {
            Err(err) => assert!(true),
            Ok(key) => assert!(false),
        }
    }

 */

}
