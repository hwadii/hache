mod md5;

pub trait Base {
    fn reset(&mut self) -> &mut Self;
    fn update(&self, value: String) -> Self;

    fn hexdigest(value: &str) -> String;
}
