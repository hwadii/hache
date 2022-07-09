mod md5;

pub trait Base {
    fn base(&mut self, value: String) -> &mut Self;
    fn reset(&mut self) -> &mut Self;
    fn update(&self, value: String) -> Self;
}
