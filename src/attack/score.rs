use phf::phf_map;

static FREQUENCIES: phf::Map<char, i32> = phf_map! {
    ' ' => 20000,
    'e' => 12700,
    't' =>  9100,
    'a' =>  8200,
    'o' =>  7500,
    'i' =>  7000,
    'n' =>  6700,
    's' =>  6300,
    'h' =>  6100,
    'r' =>  6000,
    'd' =>  4300,
    'l' =>  4000,
    'c' =>  2800,
    'u' =>  2800,
    'm' =>  2400,
    'w' =>  2400,
    'f' =>  2200,
    'g' =>  2000,
    'y' =>  2000,
    'p' =>  1900,
    'b' =>  1500,
    'v' =>   980,
    'k' =>   770,
    'j' =>   160,
    'x' =>   150,
    'q' =>   120,
    'z' =>    74,
};

pub fn score(bytes: &[u8]) -> i32 {
    bytes
        .iter()
        .map(u8::to_ascii_lowercase)
        .map(|b| FREQUENCIES.get(&b.into()).unwrap_or(&-1000))
        .sum()
}
