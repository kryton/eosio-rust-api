extern crate hmac;
extern crate sha2;

use crate::hash::hmac::Mac;
use hmac::Hmac;

use ripemd160::Ripemd160;
use sha2::Digest;
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

fn hash<D: Digest>(to_hash: &[u8]) -> Vec<u8> {
    let mut hasher = D::new();
    hasher.input(to_hash);
    hasher.result().to_vec()
}
pub fn hash_sha256(to_hash: &[u8]) -> Vec<u8> {
    hash::<Sha256>(to_hash)
}
pub fn hash_ripemd160(to_hash: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.input(to_hash);
    hasher.result().to_vec()
}

pub fn hmac(buffer: &[u8], passwd: &[u8]) -> Vec<u8> {
    let mut hasher = HmacSha256::new_varkey(passwd).expect("HMAC");
    hasher.input(buffer);

    hasher.result().code().to_vec()
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::Sha512;


    #[test]
    fn test_hmac() {
        let output = hmac(b"This is a test of HMAC", b"EOSIO");
        assert_eq!(
            output,
            [
                0x93, 0xcc, 0xbc, 0x10, 0xc9, 0x80, 0x9b, 0xf8, 0xab, 0xe2, 0x80, 0x61, 0x78, 0x13,
                0xe8, 0x1a, 0x71, 0x28, 0xd8, 0xad, 0xb2, 0x15, 0x79, 0xc4, 0x3f, 0x8d, 0x8b, 0x12,
                0x73, 0xba, 0x20, 0x47
            ]
        );
    }
    #[test]
    fn test_sha2() {
        let output256 = hash::<Sha256>(b"This is a test of Sha256");

        assert_eq!(
            output256,
            [
                0x35, 0xa4, 0x23, 0xc9, 0x61, 0x9e, 0xc6, 0xc5, 0x63, 0x41, 0x89, 0x1b, 0xd2, 0xef,
                0x26, 0x92, 0x27, 0x6b, 0xa4, 0x1a, 0x00, 0x5d, 0x0b, 0xab, 0x30, 0x18, 0x0a, 0x6f,
                0x09, 0xc6, 0x95, 0x47
            ]
        );

        let output512 = hash::<Sha512>(b"This is a test of Sha512");
        let expected512: [u8; 64] = [
            0x89, 0x59, 0x8a, 0x74, 0xe3, 0x51, 0x62, 0xcf, 0xd2, 0x8b, 0x80, 0x9d, 0x32, 0x06,
            0x18, 0x12, 0x6c, 0x84, 0x4a, 0xfa, 0xb2, 0xcb, 0xe4, 0x2d, 0xd0, 0x6d, 0xf6, 0xf1,
            0xd3, 0xba, 0xcc, 0x60, 0x13, 0x09, 0x62, 0x95, 0x1d, 0x51, 0x68, 0xcc, 0xf8, 0xd1,
            0xc8, 0x05, 0xfc, 0x4d, 0xde, 0xc7, 0x9d, 0x76, 0x6b, 0xe8, 0x08, 0x00, 0x8b, 0xcd,
            0xe6, 0x1c, 0x47, 0xc0, 0x7a, 0x8a, 0xa7, 0xdf,
        ];

        assert_eq!(output512.len(), expected512.len());
        for i in 0..expected512.len() {
            if output512[i] != expected512[i] {
                assert!(false);
            }
        }
        let output160 = hash_ripemd160(b"Ian-Kry");
        assert_eq!(
            output160,
            [
                0xbe, 0x64, 0x6f, 0x38, 0x8a, 0xf0, 0x5e, 0x6e, 0xaa, 0x4b, 0xcd, 0x0f, 0xaa, 0xcb,
                0x2a, 0x1d, 0x68, 0x58, 0x43, 0x51
            ]
        );
    }
}