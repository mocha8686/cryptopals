use phf::phf_map;

static FREQUENCIES: phf::Map<u8, i32> = phf_map! {
    b' ' => 20000,
    b'e' => 12700,
    b't' =>  9100,
    b'a' =>  8200,
    b'o' =>  7500,
    b'i' =>  7000,
    b'n' =>  6700,
    b's' =>  6300,
    b'h' =>  6100,
    b'r' =>  6000,
    b'd' =>  4300,
    b'l' =>  4000,
    b'c' =>  2800,
    b'u' =>  2800,
    b'm' =>  2400,
    b'w' =>  2400,
    b'f' =>  2200,
    b'g' =>  2000,
    b'y' =>  2000,
    b'p' =>  1900,
    b'b' =>  1500,
    b'v' =>   980,
    b'k' =>   770,
    b'j' =>   160,
    b'x' =>   150,
    b'q' =>   120,
    b'z' =>    74,
};

pub fn score(bytes: &[u8]) -> i32 {
    bytes
        .iter()
        .map(u8::to_ascii_lowercase)
        .map(|b| FREQUENCIES.get(&b).unwrap_or(&-1000))
        .sum()
}
