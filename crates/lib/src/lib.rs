pub fn x() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gets_x() {
        x()
    }
}
