use crate::Base;

const BLOCK_LENGTH: i8 = 64;
const DIGEST_LENGTH: i8 = 16;
const DIGEST_STRING_LENGTH: i8 = DIGEST_LENGTH * 2 + 1;

#[derive(Debug)]
pub struct MD5 {}

impl MD5 {
    fn new() -> Self {
        Self {}
    }
}

impl Base for MD5 {
    fn reset(&mut self) -> &mut Self {
        todo!()
    }

    fn update(&self, _value: String) -> Self {
        todo!()
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
        let digest = MD5::hexdigest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(digest, "d174ab98d277d9f5a5611c2c9f419d9f");
    }

    #[test]
    fn it_computes_md5_6() {
        let digest = MD5::hexdigest("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
        assert_eq!(digest, "57edf4a22be3c955ac49da2e2107b67a");
    }
}
