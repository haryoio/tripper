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

pub fn to_trip(origin: &str) -> String {
    let mut trip = "".to_string();
    trip = if origin.chars().skip(1).count() >= 12 {
        let mark = origin.chars().nth(1).unwrap();
        trip = if mark == '#' || mark == '$' {
            let re = Regex::new(r"^#([0-9a-fA-F]{16})([\./0-9A-Za-z]{0,2})$").unwrap();
            trip = if re.is_match(origin) {
                "???".to_string()
            } else {
                println!("mark false");
                "???".to_string()
            };
            trip
        } else {
            println!("hash true");
            let mut hasher = sha1::Sha1::new();
            hasher.update(origin[1..].as_bytes());
            let result = hasher.finalize();
            let base = base64::encode(&result);

            let a = base.replace("+", ".");
            println!("hash a: {}", a);
            a
        };
        trip
    } else {
        let otripkey = origin.chars().skip(1).collect::<String>();
        let (otripkey, ..) = encoding_rs::UTF_8.encode(&otripkey);
        let mut tripkey = BytesMut::with_capacity(otripkey.len() + 2);
        tripkey.put_slice(&otripkey);
        println!("otorip {:?}", &otripkey);
        let mut salt = BytesMut::with_capacity(tripkey.len() + 2);
        salt.put_slice(&otripkey);
        salt.put_bytes(b'H', 1);
        salt.put_bytes(b'.', 1);

        let salt = &salt[1..3];

        let re = BRegex::new(r"[^\.-z]").unwrap();
        let salt = re.replace(&salt, &b"."[..]);
        let salt = btranslate(&salt);

        println!("salt {:?} key {:?}", salt, tripkey);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_generate_trip() {
        let trip = "#istrip";
        let out = "◆/WG5qp963c";
        let b = to_trip(trip);
        assert_eq!(out, b);
    }
    #[test]
    fn test_generate_trip_2() {
        let trip = "#hogehoge";
        let out = "◆jG/Re6aTC.";
        let b = to_trip(trip);
        assert_eq!(out, b);
    }

    #[test]
    fn test_generate_trip_3() {
        let trip = "#aaaaaaaa";
        let out = "◆cR08PK3l1o";
        let b = to_trip(trip);
        assert_eq!(out, b);
    }
    #[test]
    fn test_generate_trip_4() {
        let trip = "#ｷｴｮﾘｽﾉｨｹｧﾓｬｴﾑｽ";
        let out = "◆BoilShoot/zn";
        let b = to_trip(trip);
        assert_eq!(out, b);
    }

    #[test]
    fn crypter_test() {
        let trip = b"#hogehoge\0";
        unsafe {
            let bkey = CString::from_vec_with_nul(trip.to_vec()).unwrap();
            let bsalt = CString::from_vec_with_nul(b"H.hogehoge\0".to_vec()).unwrap();
            let c = crypter(bkey.as_ptr(), bsalt.as_ptr());
            let res = CStr::from_ptr(c).to_string_lossy().into_owned();
            println!("trip {}", res);
        }
        assert!(false);
    }
}
