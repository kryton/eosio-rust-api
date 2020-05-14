// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]
//
#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate lazy_static;

use regex::Regex;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature};
use crate::hash::hash_sha256;
use crate::key_utils::{check_encode, check_decode};

pub mod hash;
mod key_utils;
pub mod errors;

use crate::errors::{Result, ErrorKind};


pub struct EOSPrivateKey {
    key_type: String,
    secret: SecretKey,
}

impl EOSPrivateKey {
    /**
     *    @arg {string} private key - like PUB_K1_base58pubkey..
     *    @return Privatekey or `Error` (invalid)
     */

    pub fn from_string(private_str: &str) -> Result<EOSPrivateKey> {
        //}, EosioEccError> {
        lazy_static! {
            static ref PRIVKEY_MATCH: Regex =
                Regex::new("^PVT_(?P<type>[A-Za-z0-9]+)_(?P<key>[A-Za-z0-9]+)$").unwrap();
        }

        if PRIVKEY_MATCH.is_match(private_str) {
            let matches = PRIVKEY_MATCH.captures(private_str).unwrap();

            let key: &str = &matches["key"];
            let key_type: &str = &matches["type"];
            if key_type == "K1" {
                match key_utils::check_decode(key.as_bytes(), key_type) {
                    Err(e) => Err(e),
                    Ok(buf) => match EOSPrivateKey::from_buffer(&buf) {
                        Err(e) => Err(e),
                        Ok(secret) => {
                            let _format = String::from("PVT");
                            let key_type = String::from(key_type);

                            Ok(EOSPrivateKey {
                                key_type,
                                secret,
                            })
                        }
                    },
                }
            } else {
                Err(ErrorKind::InvalidPrivateKeyFormat.into())
            }
        } else {
            // legacy key
            match key_utils::check_decode(private_str.as_bytes(), "sha256x2") {
                Err(e) => Err(e),
                Ok(version_key) => {
                    if version_key.len() > 1 {
                        let version = version_key[0];
                        if 0x80 == version {
                            match EOSPrivateKey::from_buffer(&version_key[1..]) {
                                Ok(secret) => {
                                    let key_type = String::from("K1");
                                    let _format = String::from("WIF");
                                    Ok(EOSPrivateKey {
                                        key_type,
                                        secret,
                                    })
                                }
                                Err(e) => Err(e),
                            }
                        } else {
                            Err(ErrorKind::InvalidPrivateKeyFormat.into())
                        }
                    } else {
                        Err(ErrorKind::InvalidPrivateKeyFormat.into())
                    }
                }
            }
        }
    }

    pub fn from_buffer(buffer: &[u8]) -> Result<SecretKey> {
        if buffer.len() == 33 && buffer[32] == 1 {
            EOSPrivateKey::from_buffer(&buffer[0..32])
        } else {
            if buffer.len() == 32 {
                Ok(SecretKey::from_slice(buffer)?)
            } else {
                Err(ErrorKind::InvalidPrivateKeyFormat.into())
            }
        }
    }
    pub fn to_public(&self) -> EOSPublicKey {
        let secp = Secp256k1::new();

        let public_key: PublicKey = PublicKey::from_secret_key(&secp, &self.secret);
        EOSPublicKey { public: public_key }
    }
    /**
        Sign data.

        @arg {String|Buffer} data - full data
        @arg {privkey|PrivateKey}  - EOSKey..

        @return {boolean}
    */
    pub fn sign(&self, data: &[u8]) -> Result<EOSSignature> {
        let hash: Vec<u8> = hash_sha256(data);
        self.sign_hash(&hash)
    }

    /**
        Sign hash.

        @arg {String|Buffer} hash - hash of data
        @arg {privkey|PrivateKey}  - EOSKey..

        @return {boolean}
    */
    pub fn sign_hash(&self, hash: &[u8]) -> Result<EOSSignature> {
        if hash.len() != 32 {
            return Err(ErrorKind::InvalidSignatureFormat.into());
        }
        let secp = Secp256k1::new();
        let message = Message::from_slice(hash)?;

        let r = secp.sign(&message, &self.secret);
        Ok(EOSSignature { sig: r })
    }
}

#[cfg(test)]
mod private_keys {
    use super::*;
    //  use crate::key_utils::check_encode;

    #[test]
    fn privatekey_construction_test() {
        let privkey = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
        let privkey2 = "PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd";
        match EOSPrivateKey::from_string(privkey) {
            Err(_) => assert!(false),
            Ok(pk) => {
                assert_eq!(pk.key_type, "K1");
            }
        }
        match EOSPrivateKey::from_string(privkey2) {
            Err(_) => assert!(false),
            Ok(pk) => {
                assert_eq!(pk.key_type, "K1");
            }
        }
    }

    #[test]
    fn private_to_public_test() {
        let privkey = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
        match EOSPrivateKey::from_string(privkey) {
            Err(e) => assert!(false),
            Ok(pk) => {
                let public = pk.to_public();
                match public.to_string() {
                    Err(_) => assert!(false),
                    Ok(s) => {
                        assert_eq!(
                            s,
                            "PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM"
                        )
                    }
                }
            }
        }
        let priv2 = "5JYgAoe1obNY2YNvoE69cwBjwpCjhM2q8cYbw4DMf6Sts1jQ5wP";
        match EOSPrivateKey::from_string(priv2) {
            Err(e) => assert!(false),
            Ok(pk) => {
                match pk.to_public().to_string() {
                    Ok(s) => assert_eq!(s,
                                        "PUB_K1_7ctUUZhtCGHnxUnh4Rg5eethj3qNS5S9fijyLMKgRsBLh8eMBB"
                    ),
                    Err(_e) => assert!(false)
                }
            }
        }
    }
}

pub struct EOSSignature {
    pub sig: Signature,
}

impl EOSSignature {
    pub fn from(buffer: &[u8]) -> Result<EOSSignature> {
        // EOS Signatures are 65 bytes long, as they have a check-digit at the start.
        // I've made this function also also traditional compact form sigs.
        if buffer.len() != 64 {
            if buffer.len() == 65 {
                let i = buffer[0];
                if i - 27 == i - 27 & 7 {
                    EOSSignature::from(&buffer[1..])
                } else {
                    Err(ErrorKind::InvalidSignatureChecksum.into())
                }
            } else {
                Err(ErrorKind::InvalidSignatureFormat.into())
            }
        } else {
            let sig = Signature::from_compact(buffer)?;
            Ok(EOSSignature { sig })
        }
    }

    pub fn from_string(sig_str: &str) -> Result<EOSSignature> {
        lazy_static! {
            static ref SIG_MATCH: Regex =
                Regex::new("^SIG_(?P<type>[A-Za-z0-9]+)_(?P<key>[A-Za-z0-9]+)$").unwrap();
        }

        if SIG_MATCH.is_match(sig_str) {
            let matches = SIG_MATCH.captures(sig_str).unwrap();

            let key: &str = &matches["key"];
            let key_type: &str = &matches["type"];
            if key_type == "K1" {
                let decoded = check_decode(key.as_bytes(), key_type)?;
                EOSSignature::from(&decoded)
            } else {
                Err(ErrorKind::InvalidSignatureFormat.into())
            }
        } else {
            Err(ErrorKind::InvalidSignatureFormat.into())
        }
    }
    /**
        Verify signed data.

        @arg {String|Buffer} data - full data
        @arg {pubkey|PublicKey} pubkey - EOSKey..

        @return {boolean}
    */
    pub fn verify(&self, data: &[u8], pubkey: EOSPublicKey) -> Result<bool> {
        let hash: Vec<u8> = hash_sha256(data);
        self.verify_hash(&hash, pubkey)
    }
    /**
        Verify a buffer of exactly 32 bytes in size (sha256(text))

        @arg {String|Buffer} dataSha256 - 32 byte buffer
        @arg {String|PublicKey} pubkey - EOSKey..

        @return {boolean}
    */
    pub fn verify_hash(&self, hash: &[u8], pubkey: EOSPublicKey) -> Result<bool> {
        if hash.len() != 32 {
            return Err(ErrorKind::InvalidSignatureFormat.into());
        }
        let secp = Secp256k1::new();
        let message = Message::from_slice(hash)?;
        secp.verify(&message, &self.sig, &pubkey.public)?;
        Ok(true)
    }
    pub fn to_eos_string(&self) -> Result<String> {
        let sig = check_encode(&self.sig.serialize_compact(), "K1")?;
        let s = ["SIG_K1_", &sig].concat();
        Ok(s)
    }
}

#[cfg(test)]
mod sig_test {
    use crate::{EOSPrivateKey, EOSPublicKey};
    use crate::errors::Result;

    #[test]
    fn sig_from() -> Result<()>{
        let sig_hex = [
            0xdc, 0x4d, 0xc2, 0x64, 0xa9, 0xfe, 0xf1, 0x7a, 0x3f, 0x25, 0x34, 0x49, 0xcf, 0x8c,
            0x39, 0x7a, 0xb6, 0xf1, 0x6f, 0xb3, 0xd6, 0x3d, 0x86, 0x94, 0x0b, 0x55, 0x86, 0x82,
            0x3d, 0xfd, 0x02, 0xae, 0x3b, 0x46, 0x1b, 0xb4, 0x33, 0x6b, 0x5e, 0xcb, 0xae, 0xfd,
            0x66, 0x27, 0xaa, 0x92, 0x2e, 0xfc, 0x04, 0x8f, 0xec, 0x0c, 0x88, 0x1c, 0x10, 0xc4,
            0xc9, 0x42, 0x8f, 0xca, 0x69, 0xc1, 0x32, 0xa2,
        ];
        let sig = super::EOSSignature::from(&sig_hex)?;
        assert_eq!(sig.to_eos_string()?,"SIG_K1_VpgDa143trq81f1YwnW3t4rPJic6QQzs2LUdSCNYeEHL8nHE3xo8AWk1LBuusDgSesqy4SR6nHt2zsLRpmeDpbBjTaA4R");

        Ok(())
    }

    #[test]
    fn sig_fromstr() -> Result<()>{
        let sig_str = "SIG_K1_KmQRYtEYYqAKMyi1RjQ3YasVuBpqpjyUM4eyQGrKvushRkVN7GdyfkJLZPqoskXPqj58BAVQdJN4CJeW5APBVjZZAQ5R6h";
        let _sig2="SIG_K1_xcuCzcbQBjUFxm5FbUi1iBLot5UjuwaaP6bwNhNF8TofjrdakpjqstPeWnQ8iNUxEC68tiZp5qDxHYHFiVpajVLuPofmYPTMpuDyFSyxEr2P6VULHrnNNidYLu3TcG8gQFqdPyhWzhotcX4VDmWTRxy1KrMjqbyxzsr3PaXDJ8tHJrsahAbQciQHbYMQoV32gc7pYbA";
        let sig = super::EOSSignature::from_string(sig_str)?;

        let sig2 = super::EOSSignature::from_string(_sig2);
        assert!(!sig2.is_ok());


        Ok(())
    }

    #[test]
    fn sig_verify_msg() -> Result<()>{
        let msg = "Regrets and I've had a few But then again, too few to mention I did what I had to do I saw it through without exemption";
        let sig_str2 = "SIG_K1_K63SvSQTHGk7GhAfg6gtZsceSnA67bKndpHRDwW7T7v8BJXY2UnVpEK7X2GvX9NMYhM5ttS4PbFNQCxsPnN7FvKPreX8Lr";
        let pubkey = "EOS7ctUUZhtCGHnxUnh4Rg5eethj3qNS5S9fijyLMKgRsBLh8eMBB";
        let sig2 = super::EOSSignature::from_string(sig_str2)?;
        let public = EOSPublicKey::from_eos_string(pubkey)?;
        let verify = sig2.verify(msg.as_bytes(), public)?;

        Ok(())
    }

    #[test]
    fn sig_sign_test() -> Result<()> {
        let priv_str = "5JYgAoe1obNY2YNvoE69cwBjwpCjhM2q8cYbw4DMf6Sts1jQ5wP";
        let msg = "Regrets and I've had a few But then again, too few to mention I did what I had to do I saw it through without exemption";
        let _sig_str = "SIG_K1_K63SvSQTHGk7GhAfg6gtZsceSnA67bKndpHRDwW7T7v8BJXY2UnVpEK7X2GvX9NMYhM5ttS4PbFNQCxsPnN7FvKPreX8Lr";

        let private = EOSPrivateKey::from_string(priv_str)?;

        let sig = private.sign(msg.as_bytes())?;
        let public = private.to_public();
        let result = sig.verify(msg.as_bytes(), public)?;
        assert!(result);

        Ok(())
    }
}

pub struct EOSPublicKey {
    pub public: PublicKey,
}

impl EOSPublicKey {
    /**
   *    @arg {string} public_key - like PUB_K1_base58pubkey..
   *    @return PublicKey or `Error` (invalid)
   */
    pub fn from_eos_string(public_key: &str) -> Result<EOSPublicKey> {
        EOSPublicKey::from_string_legacy(public_key, "EOS")
    }

    pub fn from_eos_strings(public_keys: Vec<&str>) -> Result<Vec<EOSPublicKey>> {
        let results: Vec<Result<EOSPublicKey>> = public_keys.iter().map(|s| {
            EOSPublicKey::from_eos_string(s)
        }).collect();
        let errs = results.iter().find(|f| f.is_err());
        if errs.is_some() {
            Err(ErrorKind::InvalidPubKeyFormat.into())
        } else {
            let mut part1: Vec<EOSPublicKey> = Vec::with_capacity(results.len());

            for x in results {
                match x {
                    Err(_) => {}
                    Ok(s) => part1.push(s),
                }
            }
            Ok(part1)
        }
    }

    /**
    *    @arg {string} public_key - like PUB_K1_base58pubkey..
    *    @arg {string} [pubkey_prefix = 'EOS'] - public key prefix if not contained in @public_key.
    *    @return PublicKey or `null` (invalid)
    */

    pub fn from_string_legacy(public_key: &str, pubkey_prefix: &str) -> Result<EOSPublicKey> {
        lazy_static! {
        static ref PUBKEY_MATCH: Regex =
            Regex::new("^PUB_(?P<type>[A-Za-z0-9]+)_(?P<key>[A-Za-z0-9]+)$").unwrap();
        }

        if PUBKEY_MATCH.is_match(public_key) {
            let matches = PUBKEY_MATCH.captures(public_key).unwrap();
            let key = &matches["key"];
            let key_type = &matches["type"];

            let valid_key = check_decode(key.as_bytes(), key_type)?;
            EOSPublicKey::from_buffer(valid_key)
        } else {
            // legacy
            if pubkey_prefix.len() > 0 && public_key.starts_with(pubkey_prefix) {
                let prefix_len = pubkey_prefix.len();
                let pubkey = &public_key[prefix_len..public_key.len()];
                let valid_key = check_decode(pubkey.as_bytes(), "")?;
                EOSPublicKey::from_buffer(valid_key)
            } else {
                EOSPublicKey::from_buffer(public_key.as_bytes().to_vec())
            }
        }
    }


    pub fn from_buffer(buffer: Vec<u8>) -> Result<EOSPublicKey> {
        let public_key = PublicKey::from_slice(&buffer)?;
        Ok(EOSPublicKey { public: public_key })
    }

    pub fn to_string(&self) -> Result<String> {
        let s = check_encode(&self.public.serialize(), "K1")?;
        Ok(["PUB_K1_", s.as_str()].concat())
    }
    pub fn to_eos_string(&self) -> Result<String> {
        let s = check_encode(&self.public.serialize(), "K1")?;
        Ok(["EOS", s.as_str()].concat())
    }
}

#[cfg(test)]
mod pubkey_tests {
    // use super::secp256k1::Secp256k1;
    use super::*;

    #[test]
    fn publickey_from_string_test() {
        let pubkey_k1 = "PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX";
        let pubkey_k1_inv = "PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7befX";
        let pubkey_r1 = "PUB_R1_6FPFZqw5ahYrR9jD96yDbbDNTdKtNqRbze6oTDLntrsANgQKZu";
        let pubkey_eos = "EOS67SCWnz6trqFPCtmxfjYEPSsT9JKRn4zhow8X3VTtgaEzNMULF";
        match EOSPublicKey::from_eos_string(pubkey_k1) {
            Ok(jk) => {}
            Err(e) => assert!(false),
        }
        match EOSPublicKey::from_eos_string(pubkey_r1) {
            Ok(jk) => {}
            Err(e) => assert!(false),
        }

        match EOSPublicKey::from_eos_string(pubkey_k1_inv) {
            Ok(jk) => assert!(false),
            Err(e) => {}
        }

        match EOSPublicKey::from_string_legacy(pubkey_eos, "EOS") {
            Ok(jk) => {}
            Err(e) => assert!(false),
        }
        match EOSPublicKey::from_eos_string(pubkey_eos) {
            Ok(jk) => {}
            Err(e) => assert!(false),
        }
    }
    /*
    fn back_forth(k:&str) -> String {
        match EOSPublicKey::from_string(k) {
            Err(_) => String::from("Fail_Decode"),
            Ok(pubk) => match pubk.to_string() {
                Ok(s) => s,
                Err(_) => String::from("FAIL_Encode")
            }
        }
    }
    #[test]
    fn publickey_back_forth() {

        let pubkey_k1 = "PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX";
        let pubkey_r1 = "PUB_R1_6FPFZqw5ahYrR9jD96yDbbDNTdKtNqRbze6oTDLntrsANgQKZu";
        let pubkey_eos = "EOS67SCWnz6trqFPCtmxfjYEPSsT9JKRn4zhow8X3VTtgaEzNMULF";

        let k1 =back_forth(pubkey_k1);
        let k2 =back_forth(&k1);
        assert_eq!(k1,pubkey_k1);

        let eos = back_forth(pubkey_eos);
        assert_eq!(eos,pubkey_eos);
        let r1= back_forth(pubkey_r1);
        assert_eq!(r1,pubkey_r1);



    }

     */
    /*
    fn back_forth2( in_s:&str) -> String {
        let buf1: Vec<u8> = bs58::decode(in_s).into_vec().unwrap();
        let p1 = PublicKey::from_slice(&buf1[0..33]);
        match p1 {
            Ok(s) => {
              //  let serial = s.serialize();
                match publickey_to_string(s) {
                    Err(e) => assert!(false),
                    Ok(str) => return str
                }
            },
            Err(e)=> {
                println!("{}",e);
                assert!(false)
            },
        }
        String::from("FAIL")
    }

    #[test]
    fn te() {
        let secp = Secp256k1::new();
        let s1=  "859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX";
        let s4 = "859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM";
        let s2 = "6FPFZqw5ahYrR9jD96yDbbDNTdKtNqRbze6oTDLntrsANgQKZu";
        let s3 = "67SCWnz6trqFPCtmxfjYEPSsT9JKRn4zhow8X3VTtgaEzNMULF";

        // TODO determine why checksums are different
        //assert_eq!(back_forth2(s1),s1);
        assert_eq!(back_forth2(s4),s4);

        assert_eq!(back_forth2(s2),s2);
        assert_eq!(back_forth2(s3),s3);
    }

     */
}
