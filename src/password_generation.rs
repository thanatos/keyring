//! Utilities for generating passwords.

use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng};

/// Generate a simple, impossible-to-guess password by just randomly sampling the given alphabet.
///
/// These are ugly, hard to remember passwords, but perfect if you're just copying them from a
/// keyring.
///
/// Note that `rand`'s underlying uniform sampler does the right thing to prevent bias: if it can't
/// generate a value that is within the given range (or really, a multiple of the range), it
/// re-samples.
pub fn generate_random_password<R>(rng: &mut R, alphabet: &[char], len: usize) -> crate::Secret
where
    R: Rng + CryptoRng,
{
    let mut secret = crate::Secret(String::new());
    for _ in 0..len {
        let ch = alphabet.choose(rng).unwrap();
        secret.0.push(*ch);
    }
    secret
}
