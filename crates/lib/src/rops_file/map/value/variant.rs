use strum::{AsRefStr, EnumString};

#[derive(Debug, PartialEq, AsRefStr, EnumString)]
pub enum RopsValueVariant {
    #[strum(serialize = "str")]
    String,
    #[strum(serialize = "bool")]
    Boolean,
    #[strum(serialize = "int")]
    Integer,
    #[strum(serialize = "float")]
    Float,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_string_type() {
        assert_eq!("str", RopsValueVariant::String.as_ref())
    }

    #[test]
    fn parses_string_type() {
        assert_eq!(RopsValueVariant::String, "str".parse::<RopsValueVariant>().unwrap())
    }
}
