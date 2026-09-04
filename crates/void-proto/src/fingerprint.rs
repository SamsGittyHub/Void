//! Human-verifiable fingerprints (FR-ID-03, FR-DISC-04).
//!
//! Two renderings of the same 32-byte identity fingerprint:
//!
//! - **Words** — proquints (Wilkerson, "Proquints: Identifiers that are
//!   Readable, Spellable, and Pronounceable"). Each 16-bit group becomes a
//!   consonant-vowel-consonant-vowel-consonant syllable such as `lusab`. Sixteen
//!   syllables cover the full 256-bit fingerprint.
//! - **Numbers** — 60 decimal digits in twelve groups of five, the form Signal
//!   popularised as "safety numbers".
//!
//! ## Why proquints rather than BIP-39
//!
//! The PRD says "BIP-39-style", and BIP-39's English list is the obvious
//! choice. Void uses proquints instead for one specific reason: BIP-39 requires
//! shipping and pinning a 2,048-word data file, and the word list is
//! English-only. Proquints are generated from a 20-character alphabet defined
//! in ten lines of code, so there is no data file whose integrity has to be
//! established, and the syllables are pronounceable by speakers of most
//! languages reading Latin script. `docs/DECISIONS.md#d-004` records the
//! trade-off: proquints are less memorable than dictionary words, which is why
//! the UI shows both forms and asks users to compare, not recall.
//!
//! ## Comparison discipline
//!
//! `verify_match` compares in constant time and normalises whitespace and case,
//! because a user reading digits aloud over a phone line will not reproduce
//! formatting exactly, and a comparison that fails on formatting trains users
//! to ignore mismatches.

use alloc::string::String;
use alloc::vec::Vec;

const CONSONANTS: [u8; 16] = *b"bdfghjklmnprstvz";
const VOWELS: [u8; 4] = *b"aiou";

/// Encode a 16-bit group as one proquint syllable.
fn proquint16(v: u16) -> String {
    let mut s = String::with_capacity(5);
    s.push(CONSONANTS[((v >> 12) & 0x0F) as usize] as char);
    s.push(VOWELS[((v >> 10) & 0x03) as usize] as char);
    s.push(CONSONANTS[((v >> 6) & 0x0F) as usize] as char);
    s.push(VOWELS[((v >> 4) & 0x03) as usize] as char);
    s.push(CONSONANTS[(v & 0x0F) as usize] as char);
    s
}

fn deproquint16(s: &[u8]) -> Option<u16> {
    if s.len() != 5 {
        return None;
    }
    let c = |b: u8| CONSONANTS.iter().position(|&x| x == b).map(|i| i as u16);
    let v = |b: u8| VOWELS.iter().position(|&x| x == b).map(|i| i as u16);
    Some((c(s[0])? << 12) | (v(s[1])? << 10) | (c(s[2])? << 6) | (v(s[3])? << 4) | c(s[4])?)
}

/// Render a fingerprint as sixteen proquint syllables, grouped four per line.
///
/// The grouping is a UI affordance: comparing four short groups is measurably
/// more reliable than comparing one long string.
#[must_use]
pub fn to_words(fingerprint: &[u8; 32]) -> String {
    let mut groups: Vec<String> = Vec::with_capacity(16);
    for i in 0..16 {
        let v = u16::from_be_bytes([fingerprint[2 * i], fingerprint[2 * i + 1]]);
        groups.push(proquint16(v));
    }
    groups
        .chunks(4)
        .map(|c| c.join("-"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render as a single space-free line, for QR payloads and logs.
#[must_use]
pub fn to_words_compact(fingerprint: &[u8; 32]) -> String {
    (0..16)
        .map(|i| {
            proquint16(u16::from_be_bytes([
                fingerprint[2 * i],
                fingerprint[2 * i + 1],
            ]))
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a word rendering back to a fingerprint. Whitespace and separators are
/// ignored; case is folded.
#[must_use]
pub fn from_words(s: &str) -> Option<[u8; 32]> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if cleaned.len() != 80 {
        return None;
    }
    let b = cleaned.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..16 {
        let v = deproquint16(&b[5 * i..5 * i + 5])?;
        out[2 * i..2 * i + 2].copy_from_slice(&v.to_be_bytes());
    }
    Some(out)
}

/// Render as twelve groups of five decimal digits.
///
/// Each group is one 5-byte chunk of the first 30 fingerprint bytes reduced
/// mod 100,000. Two bytes of the fingerprint are unused by this rendering,
/// which is why the word form — which covers all 32 — is the primary one and
/// the numeric form is offered for reading aloud.
#[must_use]
pub fn to_numbers(fingerprint: &[u8; 32]) -> String {
    let mut groups: Vec<String> = Vec::with_capacity(12);
    for i in 0..6 {
        let chunk = &fingerprint[5 * i..5 * i + 5];
        let v = ((chunk[0] as u64) << 32)
            | ((chunk[1] as u64) << 24)
            | ((chunk[2] as u64) << 16)
            | ((chunk[3] as u64) << 8)
            | (chunk[4] as u64);
        groups.push(alloc::format!("{:05}", v % 100_000));
        groups.push(alloc::format!("{:05}", (v / 100_000) % 100_000));
    }
    groups
        .chunks(4)
        .map(|c| c.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Compare a user-entered fingerprint against the expected one.
///
/// Accepts either rendering. Normalises formatting before comparing, and
/// compares in constant time.
#[must_use]
pub fn verify_match(expected: &[u8; 32], user_input: &str) -> bool {
    if let Some(parsed) = from_words(user_input) {
        return void_crypto::ct::eq(expected, &parsed);
    }
    // Numeric form: compare the normalised digit strings.
    let digits: String = user_input.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 60 {
        return false;
    }
    let expected_digits: String = to_numbers(expected)
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    void_crypto::ct::eq(digits.as_bytes(), expected_digits.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_roundtrip() {
        for seed in 0u8..16 {
            let fp = [seed.wrapping_mul(37).wrapping_add(11); 32];
            let w = to_words(&fp);
            assert_eq!(from_words(&w).unwrap(), fp);
            assert_eq!(from_words(&to_words_compact(&fp)).unwrap(), fp);
        }
    }

    #[test]
    fn words_are_pronounceable_syllables() {
        let fp = [0x12u8; 32];
        let compact = to_words_compact(&fp);
        let syllables: Vec<&str> = compact.split('-').collect();
        assert_eq!(syllables.len(), 16);
        for s in syllables {
            assert_eq!(s.len(), 5);
            let b = s.as_bytes();
            assert!(
                CONSONANTS.contains(&b[0])
                    && CONSONANTS.contains(&b[2])
                    && CONSONANTS.contains(&b[4])
            );
            assert!(VOWELS.contains(&b[1]) && VOWELS.contains(&b[3]));
        }
    }

    #[test]
    fn parsing_tolerates_user_formatting() {
        let fp = [0xA5u8; 32];
        let canonical = to_words_compact(&fp);
        let messy = alloc::format!("  {}  ", canonical.to_uppercase().replace('-', " \n "));
        assert_eq!(from_words(&messy).unwrap(), fp);
    }

    #[test]
    fn numbers_have_the_expected_shape() {
        let fp = [0x7Fu8; 32];
        let n = to_numbers(&fp);
        let digits: String = n.chars().filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(digits.len(), 60);
        assert_eq!(n.lines().count(), 3);
    }

    #[test]
    fn verify_match_accepts_both_forms_and_rejects_wrong_ones() {
        let fp = [0x3Cu8; 32];
        assert!(verify_match(&fp, &to_words(&fp)));
        assert!(verify_match(&fp, &to_words_compact(&fp)));
        assert!(verify_match(&fp, &to_numbers(&fp)));

        let mut other = fp;
        other[31] ^= 1;
        assert!(!verify_match(&fp, &to_words(&other)));
        assert!(!verify_match(&fp, "not a fingerprint"));
        assert!(!verify_match(&fp, ""));
    }

    #[test]
    fn distinct_fingerprints_render_distinctly() {
        let a = [1u8; 32];
        let mut b = a;
        b[0] = 2;
        assert_ne!(to_words(&a), to_words(&b));
        assert_ne!(to_numbers(&a), to_numbers(&b));
    }

    #[test]
    fn rejects_invalid_syllables() {
        // 'x' is not in the proquint alphabet.
        let bad = "xxxxx-".repeat(16);
        assert!(from_words(&bad).is_none());
        // Wrong length.
        assert!(from_words("lusab").is_none());
    }
}
