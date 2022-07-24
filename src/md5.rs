use std::fmt;
use std::num::Wrapping;

use crate::Base;

const BLOCK_LENGTH: usize = 64;
const DIGEST_LENGTH: usize = 16;
const _DIGEST_STRING_LENGTH: usize = DIGEST_LENGTH * 2 + 1;
const T_VALUES: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
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
    Wrapping(0x67452301),
    Wrapping(0xefcdab89),
    Wrapping(0x98badcfe),
    Wrapping(0x10325476),
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

pub struct MD5 {
    state: [Wrapping<u32>; 4],
    count: [u32; 2],
    buffer: [u8; BLOCK_LENGTH],
}

impl MD5 {
    fn new() -> Self {
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
            let f = value + a + Wrapping(*t_value) + Wrapping(data[g].into());
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

    fn finish(&mut self) -> [u8; DIGEST_LENGTH] {
        let mut bits: [u8; 8] = [0; 8];

        // Save the length before padding.
        for (i, bit) in bits.iter_mut().enumerate() {
            *bit = (self.count[i >> 2] >> ((i & 3) << 3)) as u8;
        }
        // Pad to 56 bytes mod 64
        self.update(
            &PADDING,
            Some(((55 - (self.count[0] as usize >> 3)) & 63) + 1),
        );

        // Append the length
        self.update(&bits, None);

        (0..DIGEST_LENGTH)
            .into_iter()
            .map(|i| (self.state[i >> 2].0 >> ((i & 3) << 3)) as u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl Base for MD5 {
    fn reset(&mut self) -> &mut Self {
        self.state = INITIAL_STATE;
        self.count.fill(0);
        self.buffer.fill(0);

        self
    }

    fn update(&mut self, value: &[u8], nbytes: Option<usize>) -> &mut Self {
        // Compute number of bytes mod 64
        let offset = ((self.count[0] >> 3) & 63) as usize;
        let nbytes = nbytes.unwrap_or(value.len());
        let nbits = (nbytes << 3) as u32;
        let mut left = nbytes;
        let mut p = value;

        if nbytes == 0 {
            return self;
        }

        // Update the number of bits
        self.count[0] += nbits;
        if self.count[0] < nbits {
            self.count[1] += 1;
        }
        self.count[1] += (nbytes >> 29) as u32;

        // Process an initial partial block
        if offset != 0 {
            let copy = if offset + nbytes as usize > BLOCK_LENGTH {
                BLOCK_LENGTH
            } else {
                nbytes
            };

            self.buffer[offset..(offset + copy)].copy_from_slice(&p[..copy]);
            if offset + copy < BLOCK_LENGTH {
                return self;
            }

            p = &p[copy..];
            left -= copy;
            self.transform(&self.buffer.clone());
        }

        // Process full blocks
        while left >= BLOCK_LENGTH {
            self.transform(&self.buffer.clone());
            p = &p[BLOCK_LENGTH..];
            left -= BLOCK_LENGTH;
        }

        // Process a final partial block
        if left != 0 {
            self.buffer[..left].copy_from_slice(&p[..left]);
        }

        self
    }

    fn hexdigest(value: &str) -> String {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_computes_md5_0() {
        let digest = MD5::hexdigest("");
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn it_computes_md5_1() {
        let digest = MD5::hexdigest("a");
        assert_eq!(digest, "0cc175b9c0f1b6a831c399e269772661");
    }

    #[test]
    fn it_computes_md5_2() {
        let digest = MD5::hexdigest("abc");
        assert_eq!(digest, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn it_computes_md5_3() {
        let digest = MD5::hexdigest("message digest");
        assert_eq!(digest, "f96b697d7cb7938d525a2f31aaf161d0");
    }

    #[test]
    fn it_computes_md5_4() {
        let digest = MD5::hexdigest("abcdefghijklmnopqrstuvwxyz");
        assert_eq!(digest, "c3fcd3d76192e4007dfb496cca67e13b");
    }

    #[test]
    fn it_computes_md5_5() {
        let digest =
            MD5::hexdigest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(digest, "d174ab98d277d9f5a5611c2c9f419d9f");
    }

    #[test]
    fn it_computes_md5_6() {
        let digest = MD5::hexdigest(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        );
        assert_eq!(digest, "57edf4a22be3c955ac49da2e2107b67a");
    }
}
