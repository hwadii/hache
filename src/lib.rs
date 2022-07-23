pub mod md5;

pub trait Base {
    fn reset(&mut self) -> &mut Self;
    fn update(&mut self, value: &[u8], nbytes: Option<usize>) -> &mut Self;

    fn hexdigest(value: &str) -> String;
}
