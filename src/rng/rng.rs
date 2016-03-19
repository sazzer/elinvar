/// Structure representing the current state of the RNG
pub struct Rng ;

/// Implementation of the RNG
impl Rng {
    /// Construct a new RNG
    /// # Examples
    /// ``` 
    /// # use libelinvar::rng::Rng;
    /// let mut rng = Rng::new();
    /// ```
    pub fn new() -> Rng {
        Rng
    }

    /// Generate a random number
    /// # Examples
    /// ```
    /// # use libelinvar::rng::Rng;
    /// let mut rng = Rng::new();
    /// let result = rng.generate();
    /// ```
    pub fn generate(&mut self) -> u32 {
        // Chosen by fair dice roll. Guaranteed to be random.
        4
    }
}

#[cfg(test)]
mod test {
    use super::Rng;

    #[test]
    fn test_roll() {
        let mut rng = Rng;
        let result = rng.generate();
        assert_eq!(4, result);
    }
}
