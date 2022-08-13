pub mod md5;

pub trait Digest {
    fn reset(&mut self) -> &mut Self;
    fn update(&mut self, value: &[u8]) -> &mut Self;

    fn hexdigest(value: &str) -> String;
}
