use crate::Base;

#[derive(Debug)]
pub struct MD5 {
    block_length: i32,
    digest_length: i32,
}

impl MD5 {
    fn new() -> Self {
        Self { block_length: 10, digest_length: 20 }
    }
}

impl Base for MD5 {
    fn base(&mut self, _value: String) -> &mut Self {
        self
    }

    fn reset(&mut self) -> &mut Self {
        self.block_length = 0;
        self.digest_length = 0;
        self
    }

    fn update(&self, _value: String) -> Self {
        todo!()
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
