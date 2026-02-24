use crate::error::{Error, Result};

#[allow(dead_code)]
pub(crate) fn check_length(value: &str, min: usize, max: usize) -> Result<()> {
    let len = value.len();
    if len < min || len > max {
        Err(Error::InvalidLength {
            min,
            max,
            actual: len,
        })
    } else {
        Ok(())
    }
}
#[allow(dead_code)]
pub(crate) fn contains_only_digits(value: &str, expected_len: usize) -> Result<()> {
    if value.len() != expected_len {
        return Err(Error::PinFormat { len: expected_len });
    }
    if !value.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::PinFormat { len: expected_len });
    }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn contains_only_charset(value: &str, charset: &str) -> Result<()> {
    if !value.chars().all(|c| charset.contains(c)) {
        return Err(Error::InvalidCharset(charset.to_string()));
    }
    Ok(())
}
#[allow(dead_code)]
pub(crate) fn contains_categories(
    value: &str,
    require_upper: bool,
    require_lower: bool,
    require_digit: bool,
    require_special: Option<&str>,
) -> Result<()> {
    if require_upper && !value.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(Error::Validation("missing uppercase character".into()));
    }
    if require_lower && !value.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(Error::Validation("missing lowercase character".into()));
    }
    if require_digit && !value.chars().any(|c| c.is_ascii_digit()) {
        return Err(Error::Validation("missing digit".into()));
    }
    if let Some(specials) = require_special {
        if !value.chars().any(|c| specials.contains(c)) {
            return Err(Error::Validation("missing special character".into()));
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn check_range(value: usize, min: usize, max: usize, field: &str) -> Result<()> {
    if value < min || value > max {
        Err(Error::Validation(format!(
            "{} must be between {} and {}, got {}",
            field, min, max, value
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_check_length() {
        assert!(check_length("abc", 2, 5).is_ok());
        assert!(check_length("a", 2, 5).is_err());
        assert!(check_length("abcdef", 2, 5).is_err());
    }
    #[test]
    fn test_contains_only_digits() {
        assert!(contains_only_digits("1234", 4).is_ok());
        assert!(contains_only_digits("12a4", 4).is_err());
        assert!(contains_only_digits("123", 4).is_err());
    }
    #[test]
    fn test_contains_only_charset() {
        assert!(contains_only_charset("abc", "abc").is_ok());
        assert!(contains_only_charset("abcd", "abc").is_err());
    }
    #[test]
    fn test_contains_categories() {
        assert!(contains_categories("Aa1!", true, true, true, Some("!@#")).is_ok());
        assert!(contains_categories("aa1!", true, true, true, Some("!@#")).is_err());
        assert!(contains_categories("AA1!", true, true, true, Some("!@#")).is_err());
        assert!(contains_categories("Aa!!", true, true, true, Some("!@#")).is_err());
    }
}
