pub fn write_varint(n: usize) -> Vec<u8> {
    if n <= 0xFC {
        (n as u8).to_le_bytes().to_vec()
    } else if n <= core::u16::MAX as usize {
        let mut bytes = vec![0xFD];
        bytes.extend_from_slice(&(n as u16).to_le_bytes());
        bytes
    } else if n <= core::u32::MAX as usize {
        let mut bytes = vec![0xFE];
        bytes.extend_from_slice(&(n as u32).to_le_bytes());
        bytes
    } else if n <= core::u64::MAX as usize {
        let mut bytes = vec![0xFF];
        bytes.extend_from_slice(&(n as u64).to_le_bytes());
        bytes
    } else {
        Vec::new()
    }
}

/// Returns the integer read and the unread buffer.
pub fn read_varint(bytes: &[u8]) -> Option<(usize, &[u8])> {
    if bytes.is_empty() {
        return None;
    }
    let prefix = bytes[0];

    if prefix == 253 {
        if bytes[1..].len() < 2 {
            None
        } else {
            Some((
                u16::from_le_bytes([bytes[1], bytes[2]]) as usize,
                &bytes[3..],
            ))
        }
    } else if prefix == 254 {
        if bytes[1..].len() < 4 {
            None
        } else {
            Some((
                u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize,
                &bytes[5..],
            ))
        }
    } else if prefix == 255 {
        if bytes[1..].len() < 8 {
            None
        } else {
            Some((
                u64::from_le_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]) as usize,
                &bytes[9..],
            ))
        }
    } else {
        Some((u8::from_le(prefix) as usize, &bytes[1..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint() {
        assert_eq!(read_varint(&write_varint(7)).unwrap().0, 7);
        assert_eq!(
            read_varint(&write_varint(core::u16::MAX as usize))
                .unwrap()
                .0,
            core::u16::MAX as usize
        );
        assert_eq!(
            read_varint(&write_varint(core::u32::MAX as usize))
                .unwrap()
                .0,
            core::u32::MAX as usize
        );
        assert_eq!(
            read_varint(&write_varint(core::u64::MAX as usize))
                .unwrap()
                .0,
            core::u64::MAX as usize
        );
    }
}
