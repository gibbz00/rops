use strum::{AsRefStr, EnumString};

#[derive(Debug, PartialEq, AsRefStr, EnumString)]
pub enum ValueType {
    #[strum(serialize = "str")]
    String,
    // .. etc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_string_type() {
        assert_eq!("str", ValueType::String.as_ref())
    }

    #[test]
    fn parses_string_type() {
        assert_eq!(ValueType::String, "str".parse::<ValueType>().unwrap())
    }
}
