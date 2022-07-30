pub fn bytes_to_u32(data: &[u8]) -> u32 {
    data.iter().enumerate().fold(0, |value, (idx, int)| {
        let mut v = (int / 16, int % 16);
        let low = u32::from(v.1) * u32::pow(16, (idx * 2) as u32);
        v = (v.0 / 16, v.0 % 16);
        let hi = u32::from(v.1) * u32::pow(16, (idx * 2 + 1) as u32);
        value + low + hi
    })
}
