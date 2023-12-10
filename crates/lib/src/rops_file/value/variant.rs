use strum::{AsRefStr, EnumString};

#[derive(Debug, PartialEq, AsRefStr, EnumString)]
pub enum ValueVariant {
    #[strum(serialize = "str")]
    String,
    // .. etc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_string_type() {
        assert_eq!("str", ValueVariant::String.as_ref())
    }

    #[test]
    fn parses_string_type() {
        assert_eq!(ValueVariant::String, "str".parse::<ValueVariant>().unwrap())
    }
}
