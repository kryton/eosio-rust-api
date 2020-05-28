use error_chain::error_chain;

impl From<Box<dyn std::error::Error>> for Error {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        Self::from(format!("{:?}", e))
    }
}

impl From<Box<dyn std::error::Error + Sync + Send>> for Error {
    fn from(e: Box<dyn std::error::Error + Sync + Send>) -> Self {
        Self::from(format!("{:?}", e))
    }
}

#[cfg(test)]
impl PartialEq for Error {
    fn eq(&self, _other: &Self) -> bool {
        // This might be Ok since we try to compare Result in tests
        false
    }
}

error_chain! {
    foreign_links {
         RegexError(regex::Error);
         Secp256k1Error(secp256k1::Error);
    }
    errors {
        SECP256k1 {
            description("Misc SECP-256k1 Error")
            display("Misc SECP-256K1 Error")
        }
        InvalidChecksum{
            description("Key has an invalid checksum")
            display("Invalid Checksum")
        }
        EncodeError{
            description("Encoding Error")
            display("Encoding Error")
        }
        InvalidPubKeyFormat {
            description("Invalid public key format")
            display("Invalid public key format")
        }
        InvalidPrivateKeyFormat{
            description("The private key is not in a format we expect. PVT_(?P<type>[A-Za-z0-9]+)_(?P<key>[A-Za-z0-9]+)")
            display("Invalid PrivateKey Format")
        }

        InvalidSignatureFormat{
            description("Invalid signature format")
            display("Invalid signature format")
        }
        InvalidSignatureChecksum{
            description("Checksum for signature failed")
            display("checksum for signature failed")
        }
        IncorrectSignature{
            description("Signature is incorrect")
            display("Signature is incorrect")
        }
        DecodeError(reason:String){
            description("Failed to decode string into key")
            display("Failed to decode string into key {}", reason)
        }

    }
}
