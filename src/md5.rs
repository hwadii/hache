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
    fn it_works() {
        let mut digest = MD5::new();
        digest.base("Hello".to_string());
        println!("{:?}", MD5::new().reset());
        assert_eq!(2, 2);
    }
}
