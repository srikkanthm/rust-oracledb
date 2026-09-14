// -----------------------------------------------------------------------------
// Oracle Native Network Encryption (ANO / NNE) primitives.
//
// Ported from the pure-Go driver `sijms/go-ora`
// (`v2/network/security/general.go` and `v2/advanced_nego/*`): AES-CBC packet
// encryption and the Diffie-Hellman key agreement that derives the session
// key. The server supplies the DH group (generator/prime/public key) during
// the ANO handshake.
// -----------------------------------------------------------------------------

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use num_bigint::BigUint;

/// Encryption algorithms negotiated by the ANO "encrypt" service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptAlgo {
    Aes128,
    Aes192,
    Aes256,
}

impl EncryptAlgo {
    /// Maps the wire algorithm id (see `encrypt_service.go`).
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            15 => Some(Self::Aes128),
            16 => Some(Self::Aes192),
            17 => Some(Self::Aes256),
            _ => None,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
}

/// AES-CBC cryptor for TNS DATA packet bodies.
///
/// Oracle uses an all-zero IV per packet and pads with `N` zero bytes
/// followed by a single count byte `N+1`. The key is the leading bytes of the
/// DH shared secret.
pub struct AesCryptor {
    algo: EncryptAlgo,
    key: Vec<u8>,
}

impl AesCryptor {
    pub fn new(algo: EncryptAlgo, key: &[u8]) -> Result<Self, String> {
        let need = algo.key_len();
        if key.len() < need {
            return Err(format!(
                "ANO AES key too short: {} bytes, need {need}",
                key.len()
            ));
        }
        Ok(Self {
            algo,
            key: key[..need].to_vec(),
        })
    }

    /// Pads, encrypts, and appends the padding-count byte.
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let pad = if data.len().is_multiple_of(16) {
            0
        } else {
            16 - (data.len() % 16)
        };
        let mut buf = Vec::with_capacity(data.len() + pad);
        buf.extend_from_slice(data);
        buf.extend(std::iter::repeat_n(0u8, pad));

        let iv = [0u8; 16];
        let mut out = vec![0u8; buf.len()];
        match self.algo {
            EncryptAlgo::Aes128 => {
                let key: [u8; 16] =
                    self.key[..16].try_into().expect("key len");
                cbc::Encryptor::<aes::Aes128>::new(
                    (&key).into(),
                    (&iv).into(),
                )
                .encrypt_padded_b2b::<NoPadding>(&buf, &mut out)
                .expect("block-aligned input");
            }
            EncryptAlgo::Aes192 => {
                let key: [u8; 24] =
                    self.key[..24].try_into().expect("key len");
                cbc::Encryptor::<aes::Aes192>::new(
                    (&key).into(),
                    (&iv).into(),
                )
                .encrypt_padded_b2b::<NoPadding>(&buf, &mut out)
                .expect("block-aligned input");
            }
            EncryptAlgo::Aes256 => {
                let key: [u8; 32] =
                    self.key[..32].try_into().expect("key len");
                cbc::Encryptor::<aes::Aes256>::new(
                    (&key).into(),
                    (&iv).into(),
                )
                .encrypt_padded_b2b::<NoPadding>(&buf, &mut out)
                .expect("block-aligned input");
            }
        }
        out.push((pad + 1) as u8);
        out
    }

    /// Strips the count byte, decrypts, and removes the zero padding.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        if !(data.len() - 1).is_multiple_of(16) {
            return Err("invalid ANO ciphertext length".to_string());
        }
        let count = data[data.len() - 1] as usize;
        if count == 0 || count > 16 {
            return Err("invalid ANO padding count".to_string());
        }
        let ct = &data[..data.len() - 1];
        if count - 1 > ct.len() {
            return Err("invalid ANO padding".to_string());
        }

        let iv = [0u8; 16];
        let mut out = vec![0u8; ct.len()];
        match self.algo {
            EncryptAlgo::Aes128 => {
                let key: [u8; 16] =
                    self.key[..16].try_into().expect("key len");
                cbc::Decryptor::<aes::Aes128>::new(
                    (&key).into(),
                    (&iv).into(),
                )
                .decrypt_padded_b2b::<NoPadding>(ct, &mut out)
                .expect("block-aligned input");
            }
            EncryptAlgo::Aes192 => {
                let key: [u8; 24] =
                    self.key[..24].try_into().expect("key len");
                cbc::Decryptor::<aes::Aes192>::new(
                    (&key).into(),
                    (&iv).into(),
                )
                .decrypt_padded_b2b::<NoPadding>(ct, &mut out)
                .expect("block-aligned input");
            }
            EncryptAlgo::Aes256 => {
                let key: [u8; 32] =
                    self.key[..32].try_into().expect("key len");
                cbc::Decryptor::<aes::Aes256>::new(
                    (&key).into(),
                    (&iv).into(),
                )
                .decrypt_padded_b2b::<NoPadding>(ct, &mut out)
                .expect("block-aligned input");
            }
        }
        out.truncate(ct.len() - (count - 1));
        Ok(out)
    }
}

/// `base^exp mod modulus`, left-padded to `out_len` bytes (the DH values are
/// fixed width; go-ora uses `big.Int.FillBytes`).
fn modpow_fixed(
    base: &[u8],
    exp: &[u8],
    modulus: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let base = BigUint::from_bytes_be(base);
    let exp = BigUint::from_bytes_be(exp);
    let modulus = BigUint::from_bytes_be(modulus);
    let mut out = base.modpow(&exp, &modulus).to_bytes_be();
    if out.len() < out_len {
        let mut padded = vec![0u8; out_len - out.len()];
        padded.extend_from_slice(&out);
        out = padded;
    }
    out
}

/// Client DH public key: `generator^private mod prime`.
pub fn dh_public_key(
    generator: &[u8],
    prime: &[u8],
    private: &[u8],
    out_len: usize,
) -> Vec<u8> {
    modpow_fixed(generator, private, prime, out_len)
}

/// Shared secret: `server_public^private mod prime`.
pub fn dh_shared_key(
    server_public: &[u8],
    private: &[u8],
    prime: &[u8],
    out_len: usize,
) -> Vec<u8> {
    modpow_fixed(server_public, private, prime, out_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_round_trip_all_sizes() {
        for (algo, key) in [
            (EncryptAlgo::Aes128, vec![0x11u8; 16]),
            (EncryptAlgo::Aes192, vec![0x22u8; 24]),
            (EncryptAlgo::Aes256, vec![0x33u8; 32]),
        ] {
            let cryptor = AesCryptor::new(algo, &key).unwrap();
            for len in [0usize, 1, 15, 16, 17, 100, 256] {
                let plain: Vec<u8> =
                    (0..len).map(|i| (i % 251) as u8).collect();
                let enc = cryptor.encrypt(&plain);
                assert!(
                    (enc.len() - 1).is_multiple_of(16),
                    "ciphertext must be block aligned"
                );
                let dec = cryptor.decrypt(&enc).unwrap();
                assert_eq!(dec, plain, "round trip failed for len {len}");
            }
        }
    }

    #[test]
    fn dh_agreement_matches() {
        // Tiny group: generator 2, prime 23. Both sides must agree.
        let generator = [2u8];
        let prime = [23u8];
        let a_priv = [5u8];
        let b_priv = [7u8];
        let a_pub = dh_public_key(&generator, &prime, &a_priv, 1);
        let b_pub = dh_public_key(&generator, &prime, &b_priv, 1);
        let a_shared = dh_shared_key(&b_pub, &a_priv, &prime, 1);
        let b_shared = dh_shared_key(&a_pub, &b_priv, &prime, 1);
        assert_eq!(a_shared, b_shared);
        // 2^(5*7) mod 23 = 4.
        assert_eq!(a_shared, vec![4u8]);
    }

    #[test]
    fn dh_fixed_width_pads_leading_zeros() {
        // 2^1 mod 23 = 2, fixed width 4 keeps leading zero bytes.
        let pub_key = dh_public_key(&[2], &[23], &[1], 4);
        assert_eq!(pub_key, vec![0, 0, 0, 2]);
    }
}
