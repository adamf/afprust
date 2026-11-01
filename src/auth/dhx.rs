//! DHCAST128 ("DHX") key exchange, compatible with AppleShare Client 3.8.4+
//! and netatalk's `uams_dhx`.
//!
//! The protocol uses fixed 128-bit Diffie-Hellman parameters and CAST5 in
//! CBC mode. This is weak by modern standards (the group is far too small)
//! but it is the strongest method classic Mac OS supports, and it never
//! sends the password in the clear.

use cast5::cipher::generic_array::GenericArray;
use cast5::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use cast5::Cast5;

pub const P: u128 = 0xBA28_73DF_B060_57D4_3F20_2474_4CEE_E75B;
pub const G: u128 = 7;
pub const S2C_IV: [u8; 8] = *b"CJalbert";
pub const C2S_IV: [u8; 8] = *b"LWallace";
pub const KEYSIZE: usize = 16;
pub const PASSWDLEN: usize = 64;

fn addmod(a: u128, b: u128, m: u128) -> u128 {
    let (s, overflow) = a.overflowing_add(b);
    if overflow || s >= m {
        s.wrapping_sub(m)
    } else {
        s
    }
}

fn mulmod(a: u128, b: u128, m: u128) -> u128 {
    let a = a % m;
    let mut r = 0u128;
    for i in (0..128).rev() {
        r = addmod(r, r, m);
        if (b >> i) & 1 == 1 {
            r = addmod(r, a, m);
        }
    }
    r
}

pub fn powmod(base: u128, exp: u128, m: u128) -> u128 {
    let mut result = 1u128 % m;
    let mut b = base % m;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = mulmod(result, b, m);
        }
        b = mulmod(b, b, m);
        e >>= 1;
    }
    result
}

fn cipher(key: &[u8; KEYSIZE]) -> Cast5 {
    // 16-byte keys are always valid for CAST5.
    Cast5::new_from_slice(key).expect("CAST5 accepts 16-byte keys")
}

/// CAST5-CBC encrypt in place (length must be a multiple of 8).
pub fn cbc_encrypt(key: &[u8; KEYSIZE], iv: &[u8; 8], data: &mut [u8]) {
    assert!(data.len() % 8 == 0);
    let c = cipher(key);
    let mut prev = *iv;
    for chunk in data.chunks_mut(8) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        let blk = GenericArray::from_mut_slice(chunk);
        c.encrypt_block(blk);
        prev.copy_from_slice(chunk);
    }
}

/// CAST5-CBC decrypt in place (length must be a multiple of 8).
pub fn cbc_decrypt(key: &[u8; KEYSIZE], iv: &[u8; 8], data: &mut [u8]) {
    assert!(data.len() % 8 == 0);
    let c = cipher(key);
    let mut prev = *iv;
    for chunk in data.chunks_mut(8) {
        let mut ct = [0u8; 8];
        ct.copy_from_slice(chunk);
        let blk = GenericArray::from_mut_slice(chunk);
        c.decrypt_block(blk);
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = ct;
    }
}

/// Server side state between FPLogin and FPLoginCont.
pub struct DhxState {
    pub id: u16,
    pub key: [u8; KEYSIZE],
    pub nonce: u128,
    pub user: String,
}

impl Drop for DhxState {
    fn drop(&mut self) {
        for b in self.key.iter_mut() {
            // SAFETY: volatile write to owned memory.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        self.nonce = 0;
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("system random number generator failed");
    b
}

/// Process the client's public value. Returns the reply payload
/// (ID, Mb, encrypted nonce+signature) and the state for FPLoginCont.
pub fn server_step1(user: String, ma: &[u8; KEYSIZE]) -> Option<(Vec<u8>, DhxState)> {
    let ma = u128::from_be_bytes(*ma);
    // Reject degenerate public values that would make K predictable.
    if ma <= 1 || ma >= P - 1 {
        return None;
    }
    let rb = loop {
        let r = u128::from_be_bytes(random_bytes::<16>()) % (P - 1);
        if r > 1 {
            break r;
        }
    };
    let mb = powmod(G, rb, P);
    let k = powmod(ma, rb, P);
    let key = k.to_be_bytes();
    let nonce = u128::from_be_bytes(random_bytes::<16>());
    let id = u16::from_be_bytes(random_bytes::<2>());

    let mut enc = [0u8; 32];
    enc[..16].copy_from_slice(&nonce.to_be_bytes());
    // bytes 16..32: server signature, all zero (as netatalk does)
    cbc_encrypt(&key, &S2C_IV, &mut enc);

    let mut reply = Vec::with_capacity(2 + 16 + 32);
    reply.extend_from_slice(&id.to_be_bytes());
    reply.extend_from_slice(&mb.to_be_bytes());
    reply.extend_from_slice(&enc);
    Some((reply, DhxState { id, key, nonce, user }))
}

/// Decrypt the FPLoginCont block (nonce+1, password). Returns the password
/// bytes (NUL padded, MacRoman) if the nonce checks out.
pub fn server_step2(state: &DhxState, block: &[u8]) -> Option<Vec<u8>> {
    if block.len() < KEYSIZE + PASSWDLEN {
        return None;
    }
    let mut buf = [0u8; KEYSIZE + PASSWDLEN];
    buf.copy_from_slice(&block[..KEYSIZE + PASSWDLEN]);
    cbc_decrypt(&state.key, &C2S_IV, &mut buf);
    let mut n = [0u8; 16];
    n.copy_from_slice(&buf[..16]);
    let got = u128::from_be_bytes(n);
    let ok = crate::util::ct_eq(&got.to_be_bytes(), &state.nonce.wrapping_add(1).to_be_bytes());
    let pw = buf[16..].to_vec();
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    if ok {
        Some(pw)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cast5_rfc2144_vector() {
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A,
        ];
        let c = cipher(&key);
        let mut b = GenericArray::clone_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        c.encrypt_block(&mut b);
        assert_eq!(b.as_slice(), &[0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2]);
    }

    #[test]
    fn powmod_small() {
        assert_eq!(powmod(4, 13, 497), 445);
        assert_eq!(powmod(G, 0, P), 1);
        assert_eq!(powmod(G, 1, P), 7);
        // Fermat: g^(p-1) = 1 mod p for prime p
        assert_eq!(powmod(G, P - 1, P), 1);
    }

    #[test]
    fn full_exchange() {
        // Simulate the client.
        let ra = u128::from_be_bytes(random_bytes::<16>()) % (P - 1);
        let ma = powmod(G, ra, P);
        let (reply, state) = server_step1("bob".into(), &ma.to_be_bytes()).unwrap();
        assert_eq!(reply.len(), 50);
        let mut mb = [0u8; 16];
        mb.copy_from_slice(&reply[2..18]);
        let k = powmod(u128::from_be_bytes(mb), ra, P).to_be_bytes();
        let mut enc = [0u8; 32];
        enc.copy_from_slice(&reply[18..50]);
        cbc_decrypt(&k, &S2C_IV, &mut enc);
        let mut nb = [0u8; 16];
        nb.copy_from_slice(&enc[..16]);
        let nonce = u128::from_be_bytes(nb);
        let mut blk = [0u8; 80];
        blk[..16].copy_from_slice(&nonce.wrapping_add(1).to_be_bytes());
        blk[16..22].copy_from_slice(b"secret");
        cbc_encrypt(&k, &C2S_IV, &mut blk);
        let pw = server_step2(&state, &blk).unwrap();
        assert_eq!(&pw[..6], b"secret");
        assert!(pw[6..].iter().all(|&b| b == 0));
        // wrong nonce
        let mut bad = [0u8; 80];
        bad[..16].copy_from_slice(&nonce.to_be_bytes());
        cbc_encrypt(&k, &C2S_IV, &mut bad);
        assert!(server_step2(&state, &bad).is_none());
    }
}
