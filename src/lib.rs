use std::{borrow::Cow, collections::HashMap};

use bytes::{BufMut, BytesMut};
use regex::bytes::Regex as BRegex;
use regex::Regex;
use sha1::Digest;
use std::ffi::CStr;
use std::os::raw::c_char;

#[link(name = "crypt", kind = "dylib")]
extern "C" {
    #[link_name = "crypt"]
    fn crypter(key: *const c_char, data: *const c_char) -> *mut c_char;
}

pub fn gen_trip(origin: &str) -> String {
    let trip = if origin.chars().skip(1).count() >= 12 {
        let mark = origin.chars().nth(1).unwrap();
        if mark == '#' || mark == '$' {
            let re = Regex::new(r"^#([0-9a-fA-F]{16})([\./0-9A-Za-z]{0,2})$").unwrap();
            if re.is_match(origin) {
                "???".to_string()
            } else {
                "???".to_string()
            }
        } else {
            make_sha_trip(origin)
        }
    } else {
        make_des_trip(origin)
    };

    format!("◆{}", trip)
}

fn btranslate(origin: &[u8]) -> Cow<[u8]> {
    let mut table = HashMap::new();
    table.insert(b':', b"A");
    table.insert(b';', b"B");
    table.insert(b'<', b"C");
    table.insert(b'=', b"D");
    table.insert(b'>', b"E");
    table.insert(b'?', b"F");
    table.insert(b'@', b"G");
    table.insert(b'[', b"a");
    table.insert(b'\\', b"b");
    table.insert(b']', b"c");
    table.insert(b'^', b"d");
    table.insert(b'_', b"e");
    table.insert(b'`', b"f");

    let mut s = Vec::with_capacity(origin.len());
    for c in origin {
        match table.get(c) {
            Some(rep) => s.extend_from_slice(*rep),
            None => s.push(*c),
        }
    }
    Cow::Owned(s)
}

fn make_sha_trip(key: &str) -> String {
    let origin = key[1..].to_string();
    let mut hasher = sha1::Sha1::new();
    let (origin, ..) = encoding_rs::SHIFT_JIS.encode(&origin);
    hasher.update(origin);
    let hash = hasher.finalize();
    let hash = base64::encode(&hash);
    let hash = hash[..12].to_string();
    let hash = hash.replace("+", ".");

    hash
}

fn make_des_trip(key: &str) -> String {
    let tripkey = key.chars().skip(1).collect::<String>();
    let (tripkey, ..) = encoding_rs::UTF_8.encode(&tripkey);
    let mut salt = BytesMut::with_capacity(tripkey.len() + 2);
    salt.put_slice(&tripkey);
    salt.put_u8(b'H');
    salt.put_u8(b'.');

    let salt = &salt[1..3];

    let re = BRegex::new(r"[^\.-z]").unwrap();
    let salt = re.replace(&salt, &b"."[..]);
    let salt = btranslate(&salt);

    let mut bsalt = BytesMut::with_capacity(salt.len() + 1);
    bsalt.put_slice(&salt);
    bsalt.put_u8(b'\0');
    let mut bkey = BytesMut::with_capacity(tripkey.len() + 1);
    bkey.put_slice(&tripkey);
    bkey.put_u8(b'\0');

    let bsalt = CStr::from_bytes_with_nul(&bsalt).unwrap();
    let bkey = CStr::from_bytes_with_nul(&bkey).unwrap();

    let res = unsafe {
        let c = crypter(bkey.as_ptr(), bsalt.as_ptr());
        CStr::from_ptr(c).to_str().unwrap()
    };

    res[res.len() - 10..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_trip() {
        let trip = "#istrip";
        let out = "◆/WG5qp963c";
        let b = gen_trip(trip);
        assert_eq!(out, b);
    }
    #[test]
    fn test_generate_trip_2() {
        let trip = "#hogehoge";
        let out = "◆jG/Re6aTC.";
        let b = gen_trip(trip);
        assert_eq!(out, b);
    }

    #[test]
    fn test_generate_trip_3() {
        let trip = "#aaaaaaaa";
        let out = "◆cR08PK3l1o";
        let b = gen_trip(trip);
        assert_eq!(out, b);
    }
    #[test]
    fn test_generate_trip_4() {
        let trip = "#ｷｴｮﾘｽﾉｨｹｧﾓｬｴﾑｽ";
        let out = "◆BoilShoot/zn";
        let b = gen_trip(trip);
        assert_eq!(out, b);
    }
}
