use error_chain::error_chain;
use crate::api_types::ErrorInt;

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


error_chain!{
        foreign_links {
            ReqwestError(::reqwest::Error);
            SerdeJsonError(serde_json::Error);
            EOSIOKeysError(eosio_client_keys::errors::Error);
            IOError(std::io::Error);
            UTF8Error(std::string::FromUtf8Error);
            LibABIEOS(libabieos_sys::errors::Error);
            Base64(base64::DecodeError);
        }
        errors {
            InvalidResponseContentType{
                description("expected a content type of application/json")
                display("invalid content type")
            }
            InvalidResponseStatus(err:ErrorInt) {
                description("EOSIO API error")
                display("EOSIO API returned {}-{}({}) {:#?}", err.code, err.name,err.what,err.details)
            }
            InvalidWASMFormat {
                description("WASM file has incorrect header")
                display("Invalid WASM file format")
            }
            InvalidABINameLength {
                description("ABI Names should be max 13 characters long")
                display("ABI Names should be max 13 characters long")
            }
            WalletMissingChainID {
                description("Wallet needs a Chain ID to sign transactions")
                display("Missing chain ID in wallet")
            }
        }
    }
