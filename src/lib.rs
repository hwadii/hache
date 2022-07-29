use std::error::Error;

pub mod md5;

pub trait Base {
    fn reset(&mut self) -> &mut Self;
    fn update(&mut self, value: &[u8]) -> &mut Self;

    fn hexdigest(value: &str) -> Result<String, Box<dyn Error>>;
}
