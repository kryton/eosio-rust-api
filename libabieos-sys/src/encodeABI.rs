// use crate::ABIEOS;

pub fn from_uint32(buff: &mut Vec<u8>, val: u32) {
    buff.push((val & 0x00ff) as u8);
    buff.push((val >> 8 & 0x00ff) as u8);
    buff.push((val >> 16 & 0x00ff) as u8);
    buff.push((val >> 24 & 0x00ff) as u8);
}

pub fn from_var_uint32(buff: &mut Vec<u8>, val: u32) {
    let mut v: u32 = val;
    while v >> 7 != 0 {
        buff.push(0x80 | (v & 0x7f) as u8);
        v >>= 7
    }
    buff.push(v as u8)
}

pub trait encodeABIEOS {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>);
}
trait encodeVarABIEOS {
    fn encodeVarABIEOS(&self, buff: &mut Vec<u8>);
}

impl encodeABIEOS for u16 {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        buff.push((self & 0x00ff) as u8);
        buff.push((self >> 8 & 0x00ff) as u8);
    }
}
impl encodeABIEOS for u8 {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        buff.push(*self);
    }
}
impl encodeABIEOS for i8 {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        buff.push(*self as u8);
    }
}

impl encodeABIEOS for u32 {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        from_uint32(buff, *self)
    }
}
impl encodeVarABIEOS for u32 {
    fn encodeVarABIEOS(&self, buff: &mut Vec<u8>) {
        from_var_uint32(buff, *self)
    }
}

impl encodeABIEOS for u64 {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        from_uint32(buff, (self & 0xffff_ffff) as u32);
        from_uint32(buff, (self / 0x1_0000_0000) as u32);
    }
}
impl encodeABIEOS for i16 {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        (*self as u16).encodeABIEOS(buff)
    }
}
impl encodeABIEOS for i32 {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        (*self as u32).encodeABIEOS(buff)
    }
}

impl encodeVarABIEOS for i32 {
    fn encodeVarABIEOS(&self, buff: &mut Vec<u8>) {
        let v: u32 = (self.checked_shl(1).unwrap_or(0) as u32 ^ (self >> 31) as u32) as u32;
        from_var_uint32(buff, v)
    }
}

impl encodeABIEOS for i64 {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        (*self as u64).encodeABIEOS(buff)
    }
}

impl encodeABIEOS for Vec<&dyn encodeABIEOS> {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        let len = self.len() as u32;
        from_var_uint32(buff, len);
        self.iter().for_each(|v| v.encodeABIEOS(buff))
    }
}

impl encodeABIEOS for String {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        self.as_str().encodeABIEOS(buff)
    }
}
impl encodeABIEOS for &str {
    fn encodeABIEOS(&self, buff: &mut Vec<u8>) {
        from_var_uint32(buff, self.len() as u32);
        buff.append(&mut self.as_bytes().to_vec());
    }
}

pub fn encodeABIEOS_null(_buff: &mut Vec<u8>) {}

pub fn encodeTimePoint(_buff: &mut Vec<u8>) {
    //TODO
    unimplemented!()
}
pub fn encodeChecksum256(_buff: &mut Vec<u8>) {
    //TODO
    unimplemented!()
}
pub fn encodeFloat64(_buff: &mut Vec<u8>) {
    //TODO
    unimplemented!()
}

pub fn encodeObject(_buff: &mut Vec<u8>) {
    //TODO
    unimplemented!()
}
pub fn encodeBytes(_buff: &mut Vec<u8>) {
    //TODO
    unimplemented!()
}
pub fn encodeSymbol(_buff: &mut Vec<u8>) {
    //TODO
    unimplemented!()
}
pub fn encodeSymbolCode(_buff: &mut Vec<u8>) {
    //TODO
    unimplemented!()
}
pub fn encodeAsset(_buff: &mut Vec<u8>) {
    //TODO
    unimplemented!()
}

#[cfg(test)]
mod test {
    use crate::encodeABI::*;
    use crate::vec_u8_to_hex;

    #[test]
    fn tst_u16() {
        let vals = [
            (1 as u16, "0100"),
            (0xffff, "ffff"),
            (0xff00, "00ff"),
            (0x00ff, "ff00"),
        ];
        for (v, b) in &vals {
            let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
            v.encodeABIEOS(buff);
            assert_eq!(vec_u8_to_hex(buff).unwrap(), *b)
        }
    }
    #[test]
    fn tst_i16() {
        let vals = [
            (1 as i16, "0100"),
            (-1, "ffff"),
            (0x7FFF, "ff7f"),
            (-32768, "0080"),
            (0x00ff, "ff00"),
        ];
        for (v, b) in &vals {
            let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
            v.encodeABIEOS(buff);
            assert_eq!(vec_u8_to_hex(buff).unwrap(), *b)
        }
    }
    #[test]
    fn tst_u32() {
        let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
        from_uint32(buff, 1);
        assert_eq!(vec_u8_to_hex(&buff).unwrap(), "01000000");
        let vals = [
            (1 as u32, "01000000"),
            (0xffff_ffff, "ffffffff"),
            (0xff00_ff00, "00ff00ff"),
            (0x0000_ffff, "ffff0000"),
        ];
        for (v, b) in &vals {
            let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
            v.encodeABIEOS(buff);
            assert_eq!(vec_u8_to_hex(buff).unwrap(), *b)
        }
    }

    #[test]
    fn tst_u64() {
        let vals = [
            (1 as u64, "0100000000000000"),
            (0xffff_ffff_ffff_ffff, "ffffffffffffffff"),
            (0x0000_ffff_0000_ffff, "ffff0000ffff0000"),
            (0xFF00_FF00_FF00_FF00, "00ff00ff00ff00ff"),
        ];
        for (v, b) in &vals {
            let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
            v.encodeABIEOS(buff);
            assert_eq!(vec_u8_to_hex(buff).unwrap(), *b)
        }
    }
    #[test]
    fn tst_var_u32() {
        let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
        from_var_uint32(buff, 1);
        assert_eq!(vec_u8_to_hex(&buff).unwrap(), "01");
        let vals = [
            (1 as u32, "01"),
            (0xffff_ffff, "ffffffff0f"),
            (0xff00_ff00, "80fe83f80f"),
            (0x0000_ffff, "ffff03"),
        ];
        for (v, b) in &vals {
            let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
            v.encodeVarABIEOS(buff);
            assert_eq!(vec_u8_to_hex(buff).unwrap(), *b)
        }
    }
    #[test]
    fn tst_var_i32() {
        let vals = [
            (1 as i32, "02"),
            (-1, "01"),
            (-2147483648, "ffffffff0f"),
            (2147483647, "feffffff0f"),
        ];
        for (v, b) in &vals {
            let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
            v.encodeVarABIEOS(buff);
            assert_eq!(vec_u8_to_hex(buff).unwrap(), *b)
        }
    }
    #[test]
    fn tst_str() {
        let vals = [(String::from("foo"), "03666f6f"), (String::from(""), "00")];
        for (v, b) in &vals {
            let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
            v.encodeABIEOS(buff);
            assert_eq!(vec_u8_to_hex(buff).unwrap(), *b)
        }
        let vals = [("foo", "03666f6f"), ("", "00")];
        for (v, b) in &vals {
            let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
            v.encodeABIEOS(buff);
            assert_eq!(vec_u8_to_hex(buff).unwrap(), *b)
        }
    }
    #[test]
    fn tst_vec() {
        let vals: Vec<&dyn encodeABIEOS> = vec![&1, &2, &3, &4];

        let buff: &mut Vec<u8> = &mut Vec::<u8>::new();
        vals.encodeABIEOS(buff);
        assert_eq!(
            vec_u8_to_hex(buff).unwrap(),
            "0401000000020000000300000004000000"
        )
    }
}
