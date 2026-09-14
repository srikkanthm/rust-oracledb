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
use sha2::{Digest, Sha256, Sha384, Sha512};

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

/// Computes the Oracle 10G (O3LOGON) password verifier.
///
/// The verifier is derived from the case-insensitive (upper-cased) username
/// and password, encoded as UTF-16BE and zero padded to a multiple of eight
/// bytes. That buffer is DES-CBC encrypted twice with an all-zero IV: the
/// first pass uses the fixed key `0x0123456789ABCDEF`, the second pass uses
/// the last ciphertext block of the first pass. Only the final block is kept.
pub fn oracle10g_verifier(user: &str, password: &[u8]) -> [u8; 8] {
    let mut data = Vec::with_capacity((user.len() + password.len()) * 2);
    for byte in user
        .bytes()
        .chain(password.iter().copied())
        .map(|b| b.to_ascii_uppercase())
    {
        data.push(0);
        data.push(byte);
    }
    while !data.len().is_multiple_of(8) {
        data.push(0);
    }
    let key1 = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let first = des_cbc_encrypt(&key1, &data);
    let key2: [u8; 8] = first[first.len() - 8..].try_into().expect("block");
    let second = des_cbc_encrypt(&key2, &data);
    second[second.len() - 8..].try_into().expect("block")
}

/// DES-CBC encryption with an all-zero IV (no padding is added; `data` must
/// already be a multiple of eight bytes).
fn des_cbc_encrypt(key: &[u8; 8], data: &[u8]) -> Vec<u8> {
    let iv = [0u8; 8];
    let mut out = vec![0u8; data.len()];
    cbc::Encryptor::<des::Des>::new(key.into(), (&iv).into())
        .encrypt_padded_b2b::<NoPadding>(data, &mut out)
        .expect("data is 8-byte aligned");
    out
}

/// Data-integrity (checksum) algorithms negotiated by the ANO "integrity"
/// service. Only the AES-keystream variants are implemented (MD5/SHA1 would
/// need an RC4 keystream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityAlgo {
    Sha256,
    Sha384,
    Sha512,
}

impl IntegrityAlgo {
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            5 => Some(Self::Sha256),
            6 => Some(Self::Sha384),
            4 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn hash_size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// A stateful AES-CBC keystream (the `OracleNetworkHash2` construction). Each
/// `next` encrypts the running buffer in place; the buffer is the previous
/// ciphertext, so the state advances exactly as Oracle's does.
struct Keystream {
    key: [u8; 16],
    iv: [u8; 16],
    buf: Vec<u8>,
}

impl Keystream {
    fn new(key: [u8; 16], iv: [u8; 16], size: usize) -> Self {
        Self {
            key,
            iv,
            buf: vec![0u8; size],
        }
    }

    fn next(&mut self) -> &[u8] {
        let mut out = vec![0u8; self.buf.len()];
        cbc::Encryptor::<aes::Aes128>::new(
            (&self.key).into(),
            (&self.iv).into(),
        )
        .encrypt_padded_b2b::<NoPadding>(&self.buf, &mut out)
        .expect("hash-sized buffer is block aligned");
        let last = out.len() - 16;
        self.iv.copy_from_slice(&out[last..]);
        self.buf = out;
        &self.buf
    }
}

/// Oracle ANO data integrity: appends/verifies a checksum derived from the DH
/// shared key. Send and receive use independent keystream state.
pub struct Integrity {
    algo: IntegrityAlgo,
    kdf_key: [u8; 16],
    kdf_iv: [u8; 16],
    kdf_buf: [u8; 32],
    encryptor: Keystream,
    decryptor: Keystream,
}

impl Integrity {
    pub fn new(
        algo: IntegrityAlgo,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Self, String> {
        if key.len() < 5 || iv.len() < 16 {
            return Err("ANO integrity key/IV too short".to_string());
        }
        let mut kdf_key = [0u8; 16];
        kdf_key[..5].copy_from_slice(&key[..5]);
        kdf_key[5] = 0xFF;
        let kdf_iv: [u8; 16] = iv[..16].try_into().expect("iv len");
        let size = algo.hash_size();
        let mut this = Self {
            algo,
            kdf_key,
            kdf_iv,
            kdf_buf: [0u8; 32],
            encryptor: Keystream::new([0u8; 16], [0u8; 16], size),
            decryptor: Keystream::new([0u8; 16], [0u8; 16], size),
        };
        this.init();
        Ok(this)
    }

    /// (Re)derives the send/receive keystreams. Called once at setup and again
    /// after every reset, matching Oracle's per-request crypto state.
    pub(crate) fn init(&mut self) {
        let mut out = [0u8; 32];
        cbc::Encryptor::<aes::Aes128>::new(
            (&self.kdf_key).into(),
            (&self.kdf_iv).into(),
        )
        .encrypt_padded_b2b::<NoPadding>(&self.kdf_buf, &mut out)
        .expect("hash-sized buffer is block aligned");
        self.kdf_buf = out;
        let mut key = [0u8; 16];
        key.copy_from_slice(&out[..16]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&out[16..]);
        // The next re-derivation uses CBC(key, iv), as Oracle does.
        self.kdf_key = key;
        self.kdf_iv = iv;

        let mut send_key = key;
        send_key[5] = 90;
        let mut recv_key = key;
        recv_key[5] = 180;
        let size = self.algo.hash_size();
        self.encryptor = Keystream::new(send_key, iv, size);
        self.decryptor = Keystream::new(recv_key, iv, size);
    }

    pub fn hash_size(&self) -> usize {
        self.algo.hash_size()
    }

    /// Returns `data || checksum`, to be encrypted afterwards.
    pub fn compute(&mut self, data: &[u8]) -> Vec<u8> {
        let keystream = self.encryptor.next().to_vec();
        let mut combined = Vec::with_capacity(data.len() + keystream.len());
        combined.extend_from_slice(data);
        combined.extend_from_slice(&keystream);
        self.algo.digest(&combined)
    }

    /// Verifies and strips the trailing checksum.
    pub fn validate(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let size = self.algo.hash_size();
        if data.len() <= size {
            return Err("data integrity check failed: short input".to_string());
        }
        let split = data.len() - size;
        let original = &data[..split];
        let received = &data[split..];
        let keystream = self.decryptor.next().to_vec();
        let mut combined =
            Vec::with_capacity(original.len() + keystream.len());
        combined.extend_from_slice(original);
        combined.extend_from_slice(&keystream);
        if self.algo.digest(&combined) == received {
            Ok(original.to_vec())
        } else {
            Err("data integrity check failed".to_string())
        }
    }
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
    fn oracle10g_verifier_matches_known_vector() {
        // passlib: oracle10.hash("password", user="username") = 872805F3F4C83365
        let verifier = oracle10g_verifier("username", b"password");
        assert_eq!(
            base16ct::upper::encode_string(&verifier),
            "872805F3F4C83365"
        );
        // The verifier is case-insensitive on both the user and password.
        assert_eq!(oracle10g_verifier("USERNAME", b"PASSWORD"), verifier);
    }

    #[test]
    fn dh_fixed_width_pads_leading_zeros() {
        // 2^1 mod 23 = 2, fixed width 4 keeps leading zero bytes.
        let pub_key = dh_public_key(&[2], &[23], &[1], 4);
        assert_eq!(pub_key, vec![0, 0, 0, 2]);
    }
}
