use crate::errors::{Result, ErrorKind};

pub const NAME_LENGTH: usize = 13;

//pub type ABIName = u64;

pub struct ABIName {
    pub value:u64
}
impl ABIName {
    pub fn from_str(string: &str) -> Result<ABIName> {
        let mut value: u64 = 0;
        let chars = string.as_bytes();
        let length = chars.len();
        if length > NAME_LENGTH {
            return Err(ErrorKind::InvalidABINameLength.into())
        }
        //let lc = string.to_ascii_lowercase();
        let mut i: usize = 0;

        while i < 12 && i < length {
            let shift: u32 = 64 - 5 * (i + 1) as u32;
            let symbol = char_to_symbol(chars[i]) & 0x1f;
            value |= symbol.checked_shl(shift).unwrap_or(0);
            i += 1;
        }
        if i > 12 {
            value |= char_to_symbol(chars[12]) & 0x0F;
        }
        Ok(ABIName{value})
    }

    pub fn to_str(&self) -> Result<String> {
        const CHARMAP: [char; 32] = ['.', '1', '2', '3', '4', '5', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

        let mut result: Vec<u8> = Vec::with_capacity(13);
        for _x in 0..=12 {
            result.push('.' as u8);
        }

        let mut tmp: u64 = self.value;
        let mut i: usize = 0;

        while i <= 12 {
            if i == 0 {
                let c = CHARMAP[(tmp & 0x0f) as usize];
                result[12 - i] = c as u8;
                tmp = tmp.checked_shr(4).unwrap_or(0);
            } else {
                let c = CHARMAP[(tmp & 0x1f) as usize];
                result[12 - i] = c as u8;
                tmp = tmp.checked_shr(5).unwrap_or(0);
            }
            i += 1;
        }
        i = 12;
        while i > 0 && result[i] == '.' as u8 {
            result.pop();
            i -= 1;
        }

       Ok(String::from_utf8(result)?)
    }
}

fn char_to_symbol(c: u8) -> u64 {
    if c >= 'a' as u8 && c <= 'z' as u8 {
        let v: u8 = (c - 'a' as u8) + 6;
        return v as u64;
    }
    if c >= '1' as u8 && c <= '5' as u8 {
        let v = (c - '1' as u8) + 1;
        return v as u64;
    }
    return 0;
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn name_to_str_test() {
        let v = ABIName { value: 0x5f2936be6a5cab80 };
        assert_eq!(v.to_str().unwrap(), "fwonhjnefmps");
        let value = 0;
        assert_eq!((ABIName { value }).to_str().unwrap(), ".");

        let value = 3589368903014285312;
        assert_eq!((ABIName { value }).to_str().unwrap(), "abc");

        let value = 614178399182651392;
        assert_eq!((ABIName { value }).to_str().unwrap(), "123");

        let value = 108209673814966326;
        assert_eq!((ABIName { value }).to_str().unwrap(), ".a.b.c.1.2.3a");

        let value = 3589369488740450304;
        assert_eq!((ABIName { value }).to_str().unwrap(), "abc.123");

        let value = 614251623682315983;
        assert_eq!((ABIName { value }).to_str().unwrap(), "12345abcdefgj");

        let value = 7754926748989239183;
        assert_eq!((ABIName { value }).to_str().unwrap(), "hijklmnopqrsj");

        let value = 576460752303423488;
        assert_eq!((ABIName { value }).to_str().unwrap(), "1");

        let value = 3458764513820540928;
        assert_eq!((ABIName { value }).to_str().unwrap(), "a");
    }

    #[test]
    fn str_to_name_test() {
        match ABIName::from_str("fwonhjnefmps") {
            Err(_) => assert!(false),
            Ok(val) => assert_eq!(val.value,0x5f2936be6a5cab80)
        }
    }
}
