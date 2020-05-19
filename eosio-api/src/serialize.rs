use crate::errors::{Result, ErrorKind};
use std::collections::HashMap;
use crate::abi::ABIName;

trait Type {
    fn name() -> String;
    fn alias_of_name() -> String;
    fn array_of() -> dyn Type;
    fn optional_of() -> dyn Type;
    fn extension_of() -> dyn Type;
    fn base_name() -> String;
    fn base() -> dyn Type;
    fn fields() -> Vec<dyn Field>;
    fn serialize(buf: &[u8], data: Vec<u8>, state: dyn SerializerState, allow_extensions: bool);
    fn deserialize(buf: &[u8], data: Vec<u8>, state: dyn SerializerState, allow_extensions: bool) -> Vec<u8>;
}

trait Field {
    fn name() -> String;
    fn type_name() -> String;
    fn abi_type() -> dyn Type;
}

trait SerializerOptions {
    fn bytes_as_uint8_array() -> bool;
}

trait SerializerState {
    fn options() -> dyn SerializerOptions;
    fn skipped_binary_extension() -> bool;
}

trait Symbol {
    /** Name of the symbol, not including precision */
    fn name() -> String;

    /** Number of digits after the decimal point */

    fn precision() -> usize;
}

trait Contract {
    fn actions() -> HashMap<String, dyn Type>;
    fn abi_types() -> HashMap<String, dyn Type>;
}

trait Authorization {
    fn actor() -> String;
    fn permission() -> String;
}

/** Action with data in structured form */
trait Action {
    fn actor() -> String;
    fn name() -> String;
    fn authorization() -> Vec<dyn Authorization>;
    fn data() -> Vec<u8>;
}

/** Action with data in serialized hex form */
trait SerializedAction {
    fn account() -> String;
    fn name() -> String;
    fn authorization() -> Vec<dyn Authorization>;
    fn data() -> String;
}

/** Serialize and deserialize data */
pub struct SerialBuffer {
    /** Amount of valid data in `array` */
    pub length: usize,

    /** Data in serialized (binary) form */
    pub array: Vec<u8>,

    /** Current position while reading (deserializing) */
    pub read_pos: usize,

    pub text_encoder: TextEncoder,
    pub text_decoder: TextDecoder,

}

impl SerialBuffer {
    /**
     * @param __namedParameters
     *    * `array`: `null` if serializing, or binary data to deserialize
     *    * `textEncoder`: `TextEncoder` instance to use. Pass in `null` if running in a browser
     *    * `textDecoder`: `TextDecider` instance to use. Pass in `null` if running in a browser
     */
    pub fn new_deserializer(text_encoder: TextEncoder, text_decoder: TextDecoder, array: Vec<u8>) -> SerialBuffer {
        SerialBuffer {
            length: array.len(),
            text_decoder,
            text_encoder,
            array,
            read_pos: 0,
        }
    }
    pub fn new_serializer(text_encoder: TextEncoder, text_decoder: TextDecoder) -> SerialBuffer {
        let array: Vec<u8> = Vec::with_capacity(1024);
        SerialBuffer {
            length: 0,
            text_decoder,
            text_encoder,
            array,
            read_pos: 0,
        }
    }

    /** Is there data available to read? */
    pub fn have_read_data(&self) -> bool {
        self.readPos < self.length
    }

    /** Restart reading from the beginning */
    pub fn restart_read(&mut self) {
        self.readPos = 0;
    }
    pub fn push_array(&mut self, v: Vec<u8>) {
        for f in v {
            self.array.push(f)
        }
        self.length = self.array.len()
    }
    pub fn push(&mut self, u: u8) {
        self.array.push(u);
        self.length += 1;
    }

    /** Get a single byte */
    pub fn get(&mut self) -> Result<u8> {
        if self.read_pos < self.length {
            let u = self.array[self.read_pos];
            self.read_pos += 1;
            Ok(u)
        } else {
            Err("Serializer Get overrun".into())
        }
    }
    /** Get a len bytes */
    pub fn get_array(&mut self, len: usize) -> Result<Vec<u8>> {
        if self.read_pos + len < self.length {
            let u = self.array[self.read_pos..self.read_pos + len];
            self.read_pos += len;
            Ok(u.to_vec())
        } else {
            Err("Serializer Get Array overrun".into())
        }
    }
    pub fn push_u16(&mut self, v: u16) {
        let u = (v & 0xff) as u8;
        self.push(u);
        let u = (v & 0xff00).checked_shr(8).unwrap_or(0) as u8;
        self.push(u);
    }

    pub fn get_u16(&mut self) -> u16{
        let mut u:u16 =0;
        u |= self.get()? as u16;
        u |= (self.get()? as u16).cheched_shl(8).unwrap_or(0);
        u
    }
    pub fn push_u32(&mut self, v: u32) {
        let u = (v & 0xff) as u8;
        self.push(u);
        let u = (v & 0xff00).checked_shr(8).unwrap_or(0) as u8;
        self.push(u);
        let u = (v & 0xff0000).checked_shr(16).unwrap_or(0) as u8;
        self.push(u);
        let u = (v & 0xff000000).checked_shr(24).unwrap_or(0) as u8;
        self.push(u);
    }

    pub fn get_u32(&mut self) -> u32{
        let mut u:u32 =0;
        u |= self.get()? as u32;
        u |= (self.get()? as u31).cheched_shl(8).unwrap_or(0);
        u |= (self.get()? as u31).cheched_shl(16).unwrap_or(0);
        u |= (self.get()? as u31).cheched_shl(24).unwrap_or(0);
        u
    }
    /** Append a `uint64`. *Caution*: `number` only has 53 bits of precision */

    pub fn push_u64(&mut self, v: u64) {
        let u:u32 = (v & 0xff_ff_ff_ff) as u32;
        self.push_u32(u);
        // 16+5. +32
        let u:u32 = (v & 0x00_05_ff_ff_00_00_00_00).checked_shr(32).unwrap_or(0) as u32;
        self.push_u32(u);
    }
    /**
    * Get a `uint64` as a `number`. *Caution*: `number` only has 53 bits of precision; some values will change.
    * `numeric.binaryToDecimal(serialBuffer.getUint8Array(8))` recommended instead
    */
    pub fn get_u64(&mut self) -> u64{
        let low = self.get_u32();
        let high = self.get_u32() & 0x00_55_ff_ff;

        let num :u64 = high.checked_shl(32).unwrap_or(0) + low ;
        num
    }
    /** Append a `varuint32` */
    pub fn push_var_u32(&mut self, v:u32) {
        let mut u:u32 = v;
        loop {
            let r = u.checked_shr(7).unwrap_or(0);
            if r != 0 {
                self.push( 0x80 | (u & 0x7f) as u8);
                u = r;
            } else {
                self.push( (u & 0xff) as u8);
                break;
            }
        }
    }
    pub fn get_var_u32(&mut self) -> u32 {
        let mut v: u32 = 0;
        let mut bit: usize = 0;
        loop {
            let b = self.get()?;
            v |= (b & 0x7f).checked_shl(bit).unwrap_or(0);
            bit += 7;
            if b & 0x80 == 0 {
                break
            }
        }
        v
    }
    pub fn push_var_i32(&mut self, v:i32) {
        self.push_var_u32(v.checked_shl(1).unwrap_or(0) ^ v.checked_shr(31).unwrap_or(0));
    }

    pub fn get_var_i32(&mut self) -> i32 {
        let v = self.get_var_u32();
        if v & 1 != 0 {
            (!v).checked_shr(1).unwrap_or(0) | 0x8000_0000
        } else {
            v.checked_shr(1).unwrap_or(0)
        }
    }
    /** Append a `float32` */
    pub fn push_f32(&mut self,v: f32) {
        eprintln!("push_f32 not supported");
        self.push_u32(0);

    }

    /** Get a `float32` */
    pub fn get_f32(&mut self) -> f32 {
        eprintln!("get_f32 not supported");
        self.get_u32() as f32
    }
    /** Append a `float64` */
    pub fn push_f64(&mut self,v: f64) {
        eprintln!("push_f64 not supported");
        self.push_u64(0);

    }
    /** Get a `float64` */
    pub fn get_f64(&mut self) -> f64 {
        eprintln!("get_f64 not supported");
        self.get_u64() as f64
    }
    pub fn push_name(&mut self, name:ABIName) {
        self.push_u64(name.value);
    }
    pub fn get_name(&mut self) -> ABIName {
        ABIName{ value:self.get_u64() }
    }
    /** Append length-prefixed binary data */
    pub fn push_bytes(&mut self, v: Vec<u8>) {
        self.push_var_u32(v.length);
        self.push_array(v);
    }
    /** Get length-prefixed binary data */
    pub fn get_bytes(&mut self) -> Vec<u8>{
        let len = self.get_var_u32();
        self.get_array(len as usize)?
    }
    /** Append a string */
    pub fn push_string(&mut self, v: string) {
        self.push_bytes(self.textEncoder.encode(v));
    }

    /** Get a string */
    pub fn get_string(&mut self) -> String {
        self.textDecoder.decode(self.get_bytes())
    }
    /** Append a `symbol_code`.
        Unlike `symbol`, `symbol_code` doesn't include a precision.
    */
    pub fn push_symbol_code(&mut self, name: string) {
        let mut a:Vec<u8> = self.text_encoder.encode(name);
        while a.len() < 8 {
            a.push(0)
        }
        self.push_array(a[0..8].to_vec());
    }
    /** Get a `symbol_code`. Unlike `symbol`, `symbol_code` doesn't include a precision. */
    pub fn get_symbol_code(&mut self)-> String {
        let a= self.get_array(8)?;
        let mut len =0;
        while (a[len] !=0) {
            len +=1 ;
        }
        self.text_decoder.decode(a[0..len])
    }

    pub fn push_symbol(&mut self, name:String, precision:u8) {
        self.push( precision & 0xff);
        let mut a:Vec<u8> = self.text_encoder.encode(name);
        while a.len() < 7 {
            a.push(0)
        }
        self.push_array(a[0..7].to_vec());
    }
    pub fn get_symbol(&mut self) -> Result<(String, u8)> {
        let precision = self.get()?;
        let a = self.get_array(7);
        let mut len =0;
        while (a[len] !=0) {
            len +=1 ;
        }
        let name = self.text_decoder.decode(a[0..len]);
        Ok((name, precision))
    }
}
/** Is this a supported ABI version? */
pub  fn supported_abi_version(version: String) -> bool{
 version.startsWith("eosio::abi/1.")
}
