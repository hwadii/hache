use std::error::Error;
use std::fmt::Write;
use std::num::Wrapping;

use crate::Base;

const BLOCK_LENGTH: usize = 64;
const DIGEST_LENGTH: usize = 16;
const _DIGEST_STRING_LENGTH: usize = DIGEST_LENGTH * 2 + 1;
const T_VALUES: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
    0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
    0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed, 0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
    0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
    0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
];
const SHIFTS: [u8; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const PADDING: [u8; 64] = [
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];
const INITIAL_STATE: [Wrapping<u32>; 4] = [
    Wrapping(0x6745_2301),
    Wrapping(0xefcd_ab89),
    Wrapping(0x98ba_dcfe),
    Wrapping(0x1032_5476),
];

const fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

const fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

const fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

const fn i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

fn slice_to_int(data: &[u8]) -> u32 {
    data.iter().enumerate().fold(0, |value, (idx, int)| {
        let mut v = (int / 16, int % 16);
        let low = u32::from(v.1) * u32::pow(16, (idx * 2) as u32);
        v = (v.0 / 16, v.0 % 16);
        let hi = u32::from(v.1) * u32::pow(16, (idx * 2 + 1) as u32);
        value + low + hi
    })
}

pub struct MD5 {
    state: [Wrapping<u32>; 4],
    count: [u32; 2],
    buffer: [u8; BLOCK_LENGTH],
}

impl MD5 {
    const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            count: [0, 0],
            buffer: [0; BLOCK_LENGTH],
        }
    }

    fn transform(&mut self, data: &[u8]) -> &mut Self {
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        for (idx, t_value) in T_VALUES.iter().enumerate() {
            let (value, g): (Wrapping<u32>, usize) = match idx {
                0..=15 => (Wrapping(f(b.0, c.0, d.0)), idx),
                16..=31 => (Wrapping(g(b.0, c.0, d.0)), (5 * idx + 1) % DIGEST_LENGTH),
                32..=47 => (Wrapping(h(b.0, c.0, d.0)), (3 * idx + 5) % DIGEST_LENGTH),
                48..=63 => (Wrapping(i(b.0, c.0, d.0)), (7 * idx) % DIGEST_LENGTH),
                _ => unreachable!(),
            };
            let part_value = slice_to_int(&data[4 * g..4 * g + 4]);
            let f = value + a + Wrapping(*t_value) + Wrapping(part_value);
            a = d;
            d = c;
            c = b;
            b += Wrapping(f.0.rotate_left(SHIFTS[idx].into()));
        }
        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;

        self
    }

    fn update_with_len(&mut self, value: &[u8], nbytes: Option<usize>) -> &mut Self {
        // Compute number of bytes mod 64
        let mut offset = ((self.count[0] >> 3) & 63) as usize;
        let nbytes = nbytes.unwrap_or(value.len());
        let nbits = (nbytes << 3) as u32;
        let p = value;

        if nbytes == 0 {
            return self;
        }

        // Update the number of bits
        self.count[0] += nbits;
        if self.count[0] < nbits {
            self.count[1] += 1;
        }
        self.count[1] += (nbytes >> 29) as u32;

        let part_len = BLOCK_LENGTH - offset;
        let mut i = part_len;

        // Transform as many times as possible
        if nbytes >= part_len {
            self.buffer[offset..(offset + part_len)].copy_from_slice(&p[..part_len]);
            self.transform(&self.buffer.clone());

            while i < part_len.saturating_sub(63) {
                let buf = self.buffer;
                self.transform(&buf[i..]);
                i += 64;
            }
            offset = 0;
        } else {
            i = 0;
        }
        // Add remaining input in buffer
        self.buffer[offset..(offset + nbytes - i)].copy_from_slice(&p[i..nbytes]);

        self
    }

    fn finish(&mut self) -> [u8; DIGEST_LENGTH] {
        // Save the length before padding.
        let bits: [u8; 8] = (0..8)
            .into_iter()
            .map(|i| (self.count[i >> 2] >> ((i & 3) << 3)) as u8)
            .collect::<Vec<_>>()
            .try_into()
            .expect("Couldn't transfrom vec into slice");

        // Pad out to 56 mod 64
        let index = (self.count[0] >> 3) & 63;
        let pad_len = if index < 56 { 56 - index } else { 120 - index };
        self.update_with_len(&PADDING, Some(pad_len as usize));

        // Append the length
        self.update(&bits);

        (0..DIGEST_LENGTH)
            .into_iter()
            .map(|i| (self.state[i >> 2].0 >> ((i & 3) << 3)) as u8)
            .collect::<Vec<_>>()
            .try_into()
            .expect("Couldn't transform vec into slice")
    }

    fn as_str(&mut self) -> Result<String, Box<dyn Error>> {
        let mut digest = String::new();

        for di in self.finish() {
            write!(&mut digest, "{:02x}", di)?;
        }

        Ok(digest)
    }
}

impl Base for MD5 {
    fn reset(&mut self) -> &mut Self {
        self.state = INITIAL_STATE;
        self.count.fill(0);
        self.buffer.fill(0);

        self
    }

    fn update(&mut self, value: &[u8]) -> &mut Self {
        self.update_with_len(value, None)
    }

    fn hexdigest(value: &str) -> Result<String, Box<dyn Error>> {
        Self::new().update(value.as_bytes()).as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_0() {
        let digest = MD5::hexdigest("");
        assert_eq!(digest.unwrap(), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_1() {
        let digest = MD5::hexdigest("a");
        assert_eq!(digest.unwrap(), "0cc175b9c0f1b6a831c399e269772661");
    }

    #[test]
    fn test_md5_2() {
        let digest = MD5::hexdigest("abc");
        assert_eq!(digest.unwrap(), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_md5_3() {
        let digest = MD5::hexdigest("message digest");
        assert_eq!(digest.unwrap(), "f96b697d7cb7938d525a2f31aaf161d0");
    }

    #[test]
    fn test_md5_4() {
        let digest = MD5::hexdigest("abcdefghijklmnopqrstuvwxyz");
        assert_eq!(digest.unwrap(), "c3fcd3d76192e4007dfb496cca67e13b");
    }

    #[test]
    fn test_md5_5() {
        let digest =
            MD5::hexdigest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(digest.unwrap(), "d174ab98d277d9f5a5611c2c9f419d9f");
    }

    #[test]
    fn test_md5_6() {
        let digest = MD5::hexdigest(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        );
        assert_eq!(digest.unwrap(), "57edf4a22be3c955ac49da2e2107b67a");
    }

    #[test]
    fn test_reset() {
        let digest = MD5::new().update(b"a").reset().as_str();
        assert_eq!(digest.unwrap(), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
