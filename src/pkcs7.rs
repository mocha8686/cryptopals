use std::borrow::Cow;

use itertools::chain;

use crate::data::Data;

pub(crate) fn pad(data: &Data, block_size: u8) -> Data {
    let trailing_len: u8 = (data.bytes().len() % block_size as usize) as u8;
    let remaining_len = (block_size - trailing_len) % block_size;

    chain(
        data.bytes().iter().copied(),
        vec![remaining_len; remaining_len as usize],
    )
    .collect::<Box<_>>()
    .into()
}

pub(crate) fn unpad(data: &Data) -> Cow<Data> {
    let data = Cow::Borrowed(data);
    let bytes = data.bytes().clone();
    let last_byte = bytes.last().copied().unwrap_or(0) as usize;

    if last_byte > bytes.len()
        || !bytes
            .iter()
            .rev()
            .take(last_byte)
            .all(|&b| b as usize == last_byte)
    {
        data
    } else {
        Cow::Owned(Data::from(
            data.bytes()
                .iter()
                .take(bytes.len() - last_byte)
                .copied()
                .collect::<Vec<u8>>(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn pad_test() -> Result<()> {
        assert_eq!(
            pad(&"YELLOW SUBMARINE".parse()?, 20),
            "YELLOW SUBMARINE\x04\x04\x04\x04".parse()?
        );

        Ok(())
    }

    #[test]
    fn unpad_test() -> Result<()> {
        assert_eq!(
            unpad(&"YELLOW SUBMARINE\x04\x04\x04\x04".parse()?),
            Cow::Owned("YELLOW SUBMARINE".parse()?)
        );

        Ok(())
    }

    #[test]
    fn unpad_borrow_tests() -> Result<()> {
        assert_eq!(
            unpad(&"YELLOW SUBMARINE".parse()?),
            Cow::Borrowed(&"YELLOW SUBMARINE".parse()?),
        );

        assert_eq!(
            unpad(&"YELLOW SUBMARINE\x05\x05\x05\x05".parse()?),
            Cow::Borrowed(&"YELLOW SUBMARINE\x05\x05\x05\x05".parse()?),
        );

        assert_eq!(
            unpad(&"YELLOW SUBMARINE\x03\x03\x03\x03".parse()?),
            Cow::Owned("YELLOW SUBMARINE\x03".parse()?),
        );

        Ok(())
    }

    #[test]
    fn unpad_edge_cases() -> Result<()> {
        assert_eq!(
            unpad(&"YELLOW SUBMARINE\x00".parse()?),
            Cow::Borrowed(&"YELLOW SUBMARINE\x00".parse()?),
        );

        assert_eq!(
            unpad(&"YELLOW SUBMARINE\x7f".parse()?),
            Cow::Borrowed(&"YELLOW SUBMARINE\x7f".parse()?),
        );

        Ok(())
    }
}
