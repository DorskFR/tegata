use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc().replace_nanosecond(0).unwrap_or_else(|_| OffsetDateTime::now_utc())
}

pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Four groups of four lowercase letters: about 75 bits, easy to type on a phone.
pub fn password() -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    let groups: Vec<String> = (0..4)
        .map(|_| {
            (0..4).map(|_| char::from(ALPHABET[rand::random_range(0..ALPHABET.len())])).collect()
        })
        .collect();
    groups.join("-")
}

/// Lowercase, colon separated hex, the form OpenBao uses for serial numbers.
pub fn format_serial(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

pub fn normalize_serial(serial: &str) -> String {
    let hex: String =
        serial.chars().filter(char::is_ascii_hexdigit).map(|c| c.to_ascii_lowercase()).collect();
    let trimmed = hex.trim_start_matches('0');
    let padded = if trimmed.len() % 2 == 1 { format!("0{trimmed}") } else { trimmed.to_owned() };
    hex::decode(&padded).map(|b| format_serial(&b)).unwrap_or(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_shape() {
        let p = password();
        assert_eq!(p.len(), 19);
        assert_eq!(p.split('-').count(), 4);
        assert!(p.chars().all(|c| c == '-' || c.is_ascii_lowercase()));
    }

    #[test]
    fn serials_normalize() {
        assert_eq!(normalize_serial("0A:0b:FF"), "0a:0b:ff");
        assert_eq!(normalize_serial("00:0a:0b"), "0a:0b");
        assert_eq!(normalize_serial("a0b"), "0a:0b");
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(random_token(), random_token());
        assert_eq!(random_token().len(), 43);
    }
}
