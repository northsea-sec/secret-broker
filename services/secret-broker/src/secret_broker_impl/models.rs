use zeroize::Zeroize;

/// Response from unwrap - plaintext is base64-encoded.
/// Implements Drop to zeroize the plaintext string on deallocation.
#[derive(Debug)]
pub struct UnwrapResponse {
    pub plaintext: String,
}

impl Drop for UnwrapResponse {
    fn drop(&mut self) {
        // SAFETY: String::as_mut_vec is unsafe but we only write zeros.
        // This bypasses String immutability to ensure the plaintext is
        // wiped from memory, not just deallocated.
        unsafe {
            self.plaintext.as_mut_vec().zeroize();
        }
    }
}
