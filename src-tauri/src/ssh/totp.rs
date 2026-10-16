//! Time-based one-time passwords (RFC 6238), so a host's 2FA code can be
//! filled in at login the way an authenticator app would show it.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    fn name(self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Clone)]
pub struct Totp {
    /// Base32 as entered, normalized (upper case, no spaces or padding).
    secret_base32: String,
    secret: Vec<u8>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: TotpAlgorithm,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// The current code, for showing next to a host.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    /// Seconds until the next code.
    pub remaining: u64,
    pub period: u64,
}

impl Totp {
    /// A base32 secret as services show it (any case, spaces and dashes
    /// allowed), or an `otpauth://totp/...` URI from the QR code.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        // `get` instead of slicing: input is typed text and may not be ASCII.
        if input.get(..10).is_some_and(|prefix| prefix.eq_ignore_ascii_case("otpauth://")) {
            return Self::parse_uri(&input[10..]);
        }
        Self::new(input, 6, 30, TotpAlgorithm::Sha1)
    }

    fn new(secret: &str, digits: u32, period: u64, algorithm: TotpAlgorithm) -> Result<Self, String> {
        let secret_base32: String = secret
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>()
            .trim_end_matches('=')
            .to_string();
        if secret_base32.is_empty() {
            return Err("The 2FA secret is empty".to_string());
        }
        let secret = base32_decode(&secret_base32)
            .ok_or("The 2FA secret isn't valid base32 (letters A-Z and digits 2-7)")?;
        // RFC 4226 asks for at least 128 bits; common services use 80.
        if secret.len() < 10 {
            return Err("The 2FA secret is too short".to_string());
        }
        Ok(Totp { secret_base32, secret, digits, period, algorithm })
    }

    fn parse_uri(rest: &str) -> Result<Self, String> {
        let (kind, rest) = rest.split_once('/').ok_or("Not an otpauth URI")?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err("Only time-based (TOTP) codes are supported".to_string());
        }
        let query = rest.split_once('?').map(|(_, query)| query).unwrap_or_default();
        let (mut secret, mut digits, mut period, mut algorithm) = (None, 6, 30, TotpAlgorithm::Sha1);
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value);
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(value),
                "digits" => {
                    digits = value
                        .parse()
                        .ok()
                        .filter(|d| (6..=8).contains(d))
                        .ok_or("The otpauth URI asks for an unsupported number of digits")?
                }
                "period" => {
                    period = value
                        .parse()
                        .ok()
                        .filter(|p| (1..=600).contains(p))
                        .ok_or("The otpauth URI has an invalid period")?
                }
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        other => return Err(format!("Unsupported 2FA algorithm {other}")),
                    }
                }
                _ => {}
            }
        }
        let secret = secret.ok_or("The otpauth URI has no secret")?;
        Self::new(&secret, digits, period, algorithm)
    }

    /// How it's kept (encrypted) in the vault.
    pub fn to_uri(&self) -> String {
        format!(
            "otpauth://totp/Termimus?secret={}&digits={}&period={}&algorithm={}",
            self.secret_base32,
            self.digits,
            self.period,
            self.algorithm.name()
        )
    }

    pub fn code_at(&self, unix_time: u64) -> String {
        let counter = (unix_time / self.period).to_be_bytes();
        macro_rules! hmac {
            ($digest:ty) => {{
                let mut mac = Hmac::<$digest>::new_from_slice(&self.secret).expect("HMAC takes any key length");
                mac.update(&counter);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        let digest = match self.algorithm {
            TotpAlgorithm::Sha1 => hmac!(sha1::Sha1),
            TotpAlgorithm::Sha256 => hmac!(sha2::Sha256),
            TotpAlgorithm::Sha512 => hmac!(sha2::Sha512),
        };
        // Dynamic truncation (RFC 4226 section 5.3).
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        let code = binary % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    pub fn current(&self) -> TotpCode {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default();
        TotpCode {
            code: self.code_at(now),
            remaining: self.period - now % self.period,
            period: self.period,
        }
    }
}

/// RFC 4648 base32 without padding; leftover bits at the end are ignored, as
/// authenticator apps do.
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut bits: u64 = 0;
    let mut count = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    for c in input.chars() {
        let value = match c {
            'A'..='Z' => c as u64 - 'A' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return None,
        };
        bits = (bits << 5) | value;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(high), Some(low)) => {
                    out.push((high * 16 + low) as u8);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc(secret: &[u8], algorithm: TotpAlgorithm) -> Totp {
        // Base32 of the RFC 6238 test secrets, built with the same alphabet.
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut base32 = String::new();
        let (mut bits, mut count) = (0u64, 0);
        for &byte in secret {
            bits = (bits << 8) | byte as u64;
            count += 8;
            while count >= 5 {
                count -= 5;
                base32.push(ALPHABET[((bits >> count) & 31) as usize] as char);
            }
        }
        if count > 0 {
            base32.push(ALPHABET[((bits << (5 - count)) & 31) as usize] as char);
        }
        Totp::new(&base32, 8, 30, algorithm).unwrap()
    }

    #[test]
    fn rfc6238_test_vectors() {
        let sha1 = rfc(b"12345678901234567890", TotpAlgorithm::Sha1);
        let sha256 = rfc(b"12345678901234567890123456789012", TotpAlgorithm::Sha256);
        let sha512 = rfc(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            TotpAlgorithm::Sha512,
        );
        let vectors: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (time, a, b, c) in vectors {
            assert_eq!(sha1.code_at(time), a, "SHA1 at {time}");
            assert_eq!(sha256.code_at(time), b, "SHA256 at {time}");
            assert_eq!(sha512.code_at(time), c, "SHA512 at {time}");
        }
    }

    #[test]
    fn secrets_and_otpauth_uris() {
        // Grouped and lower case, as sites often show it.
        let totp = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!((totp.digits, totp.period, totp.algorithm), (6, 30, TotpAlgorithm::Sha1));
        assert_eq!(totp.code_at(0).len(), 6);

        let totp = Totp::parse(
            "otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!((totp.digits, totp.period, totp.algorithm), (8, 60, TotpAlgorithm::Sha256));
        // The stored form reads back the same.
        let again = Totp::parse(&totp.to_uri()).unwrap();
        assert_eq!(again.code_at(1_700_000_000), totp.code_at(1_700_000_000));

        assert!(Totp::parse("").is_err());
        // Non-ASCII around the prefix length is rejected, not a crash.
        assert!(Totp::parse("abcdefghié").is_err());
        assert!(Totp::parse("JBSWY3DP\u{2009}EHPK3PXP").is_ok(), "thin-space grouping");
        assert!(Totp::parse("not base32!").is_err());
        assert!(Totp::parse("JBSWY3DP").is_err(), "too short");
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").is_err());
        assert!(Totp::parse("otpauth://totp/x?issuer=nobody").is_err());
    }
}
