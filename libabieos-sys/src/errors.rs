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

error_chain! {
    foreign_links {
        UTF8Error2(std::str::Utf8Error);
        UTF8Error(std::string::FromUtf8Error);
        FFIError(std::ffi::NulError);
    }
    errors {
        ABIEOS(s:String){
            description("ABIEOS ")
            display("ABIEOS {}",s)
        }
         ABIEOS_INT {
            description("ABIEOS Error Internal")
            display("ABIEOS Error Internal")
        }
        ABIEOS_LOOP {
            description("ABIEOS Stuck in internal loop")
            display("ABIEOS Stuck in internal loop")
        }
        ABIEOS_VARUINT_ENCODING {
            description("Invalid VarUInt encoding")
            display("ABIEOS Invalid VarUInt encoding")
        }
    }
}
