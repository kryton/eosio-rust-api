extern crate rand;

use std::f64;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use self::rand::thread_rng;
use crate::hash::{hash_ripemd160, hash_sha256};

use rand::distributions::Standard;
use rand::rngs::OsRng;
use rand::Rng;
use crate::errors::{ErrorKind, Result};

lazy_static! {
    pub static ref ENTROPY_COUNT: Mutex<usize> = Mutex::new(0);
    static ref ENTROPY_POS: Mutex<usize> = Mutex::new(0);
    static ref EXTERNAL_ENTROPY_ARRAY: Mutex<Vec<u8>> = Mutex::new(random_bytes(101));
}

#[allow(dead_code)]
pub fn random32_byte_buffer(cpu_entropy_bits: usize, safe: bool) -> Vec<u8> {
    match EXTERNAL_ENTROPY_ARRAY.lock() {
        Ok(ext_entropy_array) => {
            let ent_cnt: usize = *ENTROPY_COUNT.lock().unwrap();
            if safe {
                assert!(ent_cnt >= 128);
            }
            let mut hash_array: Vec<Vec<u8>> = vec![];
            let mut cpu_ent: Vec<Vec<u8>> = vec![];
            // todo: replace to_string part and just use raw bytes
            for f in cpu_entropy(cpu_entropy_bits) {
                let s = format!("{}", f);
                cpu_ent.push(s.into_bytes());
            }

            let mut cpu_ent_t: Vec<u8> = vec![];
            cpu_ent
                .iter()
                .for_each(|v| v.iter().for_each(|u| cpu_ent_t.push(*u)));
            let mut entropy: Vec<u8> = vec![];
            ext_entropy_array.iter().for_each(|u| entropy.push(*u));

            hash_array.push(random_bytes(32));
            hash_array.push(os_random_bytes(32));
            hash_array.push(cpu_ent_t);
            hash_array.push(entropy);
            let mut flattened: Vec<u8> = vec![];
            hash_array
                .iter()
                .for_each(|v| v.iter().for_each(|u| flattened.push(*u)));
            let f: &[u8] = flattened.as_slice();
            return hash_sha256(f);
        }
        Err(_) => panic!("Random 32byte buffer fail"),
    }
}
#[allow(dead_code)]
pub fn random_bytes(num: usize) -> Vec<u8> {
    thread_rng().sample_iter(&Standard).take(num).collect()
}
#[allow(dead_code)]
pub fn os_random_bytes(num: usize) -> Vec<u8> {
    OsRng.sample_iter(&Standard).take(num).collect()
}

/**
    Adds entropy.  This may be called many times while the amount of data saved
    is accumulatively reduced to 101 integers.  Data is retained in RAM for the
    life of this module.

    @example React <code>
    componentDidMount() {
        this.refs.MyComponent.addEventListener("mousemove", this.onEntropyEvent, {capture: false, passive: true})
    }
    componentWillUnmount() {
        this.refs.MyComponent.removeEventListener("mousemove", this.onEntropyEvent);
    }
    onEntropyEvent = (e) => {
        if(e.type === 'mousemove')
            key_utils.addEntropy(e.pageX, e.pageY, e.screenX, e.screenY)
        else
            console.log('onEntropyEvent Unknown', e.type, e)
    }
    </code>
*/
#[allow(dead_code)]
pub fn add_entropy(ints: &[u8]) {
    match EXTERNAL_ENTROPY_ARRAY.lock() {
        Ok(mut ext_entropy_array) => {
            let mut ent_cnt: usize = *ENTROPY_COUNT.lock().unwrap();
            let mut ent_pos: usize = *ENTROPY_POS.lock().unwrap();

            let mut pos = 0;
            ent_cnt += ints.len();
            let mut i2: u8 = 0;
            for i in ints {
                ent_pos += 1;
                pos = ent_pos % 101;
                let val = ext_entropy_array[pos];
                if val >= u8::max_value() - i {
                    ext_entropy_array[pos] = 0;
                } else {
                    ext_entropy_array[pos] = val + i;
                }
                i2 = ext_entropy_array[pos]
            }
            if i2 >= u8::max_value() {
                ext_entropy_array[pos] = 0;
            }
            *ENTROPY_COUNT.lock().unwrap() = ent_cnt;
            *ENTROPY_POS.lock().unwrap() = ent_pos;
        }
        Err(_) => panic!("mutex"),
    }
}

/**
    This runs in just under 1 second and ensures a minimum of cpu_entropy_bits
    bits of entropy are gathered.

    Based on more-entropy. @see https://github.com/keybase/more-entropy/blob/master/src/generator.iced

    @arg [cpu_entropy_bits = 128]
    @return {array} counts gathered by measuring variations in the CPU speed during floating point operations.
*/
#[allow(dead_code)]
pub fn cpu_entropy(cpu_entropy_bits: usize) -> Vec<f64> {
    let mut collected: Vec<f64> = vec![];
    let mut last_count: f64 = -1.0;
    let mut low_entropy_samples: u32 = 0;
    while collected.len() < cpu_entropy_bits {
        let count = floating_point_count();
        if last_count != -1.0 {
            let delta = count - last_count;
            if delta.abs() < 1.0 {
                low_entropy_samples += 1;
            } else {
                // how many bits of entropy were in this sample
                let bits = (delta.abs().log2() + 1.0).floor();
                if bits < 4.0 {
                    if bits < 2.0 {
                        low_entropy_samples += 1;
                    }
                    continue;
                } else {
                    collected.push(delta)
                }
            }
        }
        last_count = count
    }
    if low_entropy_samples > 10 {
        let pct = low_entropy_samples as f64 / cpu_entropy_bits as f64 * 100.0;
        // Is this algorithm getting inefficient?
        eprintln!("WARN: {:.3}% low CPU entropy re-sampled", pct);
    }
    return collected;
}

/**
    @private
    Count while performing floating point operations during a fixed time
    (7 ms for example).  Using a fixed time makes this algorithm
    predictable in runtime.
*/
#[allow(dead_code)]
fn floating_point_count() -> f64 {
    let work_min_ms = Duration::new(0, 7 * 1000000); // 7ms
    let start = Instant::now();
    let mut i: f64 = 0.0;
    let mut x: f64 = 0.0;
    // let mut duration = start.elapsed();

    while start.elapsed() < work_min_ms {
        i += 1.0;
        x = (x + i).log(10.0).sqrt().sin();
        //    duration = start.elapsed();
    }
    return i;
}

/**
  @arg {Buffer} keyBuffer data
  @arg {string} keyType = sha256x2, K1, etc
  @return {string} checksum encoded base58 string
*/

pub fn check_encode(key_buffer: &[u8], key_type: &str) -> Result<String> {
    match key_type {
        "sha256x2" => {
            let res = hash_sha256(&hash_sha256(key_buffer));
            let checksum = &res[0..4];

            let mut buf: Vec<u8> = vec![];
            buf.extend(key_buffer);
            buf.extend(checksum);
            Ok(bs58::encode(buf).into_string())
        }
        _ => {
            let hash = hash_ripemd160(key_buffer);
            let checksum = &hash[0..4];
            let mut buf: Vec<u8> = vec![];
            buf.extend(key_buffer);
            buf.extend(checksum);
            Ok(bs58::encode(buf).into_string())
        }
    }
}

/**
  @arg {Buffer} keyString data
  @arg {string} keyType = sha256x2, K1, etc
  @return {string} checksum encoded base58 string
*/
pub fn check_decode(key_string: &[u8], key_type: &str) -> Result<Vec<u8>> { // , EosioEccError> {
    let buf: Vec<u8> = bs58::decode(key_string).into_vec().unwrap();
    let buffer_len = buf.len();
    if buffer_len <= 4 {
        return Err(ErrorKind::DecodeError(String::from("Key is too short")).into());
    } else {
        let post_len: usize = buffer_len.checked_sub(4).unwrap_or(0);
        let checksum = &buf[post_len..buffer_len];
        let key = &buf[0..post_len];
        let new_check: Vec<u8> = match key_type {
            "sha256x2" => {
                let buf = &hash_sha256(&hash_sha256(&key))[0..4];
                buf.to_vec()
            }
            _ => {
                let concat = [key, key_type.as_bytes()].concat();
                hash_ripemd160(&concat)[0..4].to_vec()
            }
        };
        if checksum.to_vec() == new_check {
            Ok(key.to_vec())
        } else {
            Err(ErrorKind::InvalidChecksum.into())
        }
    }
}
/*
mod tests {
    use super::*;

    #[test]
    fn hi() {
        /*
        //add_entropy(&os_random_bytes(200));
        add_entropy(&random_bytes(200));
        cpu_entropy(128);
        let x = random32_byte_buffer(128,true);
        let y = random32_byte_buffer(128,true);
        println!("Cnt {}", ENTROPY_COUNT.lock().unwrap());
        println!("Pos {}", ENTROPY_POS.lock().unwrap());
        println!("X {} Y{}", x[0],y[0])

         */
    }
}
*/
