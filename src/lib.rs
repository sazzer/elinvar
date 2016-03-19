pub fn hello() -> String {
    return "Elinvar".to_owned();
}

#[cfg(test)]
mod test {
    use super::hello;

    #[test]
    fn test_hello() {
        assert_eq!("Elinvar", hello());
    }
}
