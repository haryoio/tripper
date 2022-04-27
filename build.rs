extern crate cc;
fn main() {
    cc::Build::new()
        .file("src/c/crypter.c")
        .include("src/c")
        .flag("-lcrypt")
        .warnings(false)
        .compile("libcrypter");
}
