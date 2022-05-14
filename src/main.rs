use rand;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, LineEnding},
    PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey,
};
use std::fs;
use std::process::Command;
use std::path;

fn main() {
    let dir = "/tmp/hreg-rsa/";
    gen(&dir);
    let p = path::Path::new(&dir);

    let kpem = fs::read_to_string(p.join("key.pem")).unwrap();
    let ppem = fs::read_to_string(p.join("pub.pem")).unwrap();
    let private_key = RsaPrivateKey::from_pkcs1_pem(&kpem).unwrap();
    let public_key = RsaPublicKey::from_pkcs1_pem(&ppem).unwrap();

    println!("to test ...");
    crypy_test(&private_key, &public_key);
    sign_test(&private_key, &public_key);
}

#[allow(dead_code)]
fn gen(dir: &str) {
    let mut rng = rand::thread_rng();
    let bits = 1024;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let k = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();


    fs::write(format!("{}{}", dir, "key.pem"), k.as_str()).unwrap();
    let mut cmd = Command::new("openssl");
    cmd.args([
        "rsa",
        "-in",
        "key.pem",
        "-RSAPublicKey_out",
        "-out",
        "pub.pem",
    ]);
    cmd.current_dir("/tmp/hreg-rsa");
    let mut c = cmd.spawn().unwrap();
    c.wait().unwrap();

    println!("gen rsa done");

    // println!("{}", k.as_str());
}

fn crypy_test(private_key: &RsaPrivateKey, public_key: &RsaPublicKey) {
    let mut rng = rand::thread_rng();

    // Encrypt
    let data = b"hello world";
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = public_key
        .encrypt(&mut rng, padding, &data[..])
        .expect("failed to encrypt");
    assert_ne!(&data[..], &enc_data[..]);

    // Decrypt
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let dec_data = private_key
        .decrypt(padding, &enc_data)
        .expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);

    println!("crypy_test done")
}

fn sign_test(private_key: &RsaPrivateKey, public_key: &RsaPublicKey) {
    let data = b"hello world";
    let padding = PaddingScheme::new_pkcs1v15_sign(Option::None);
    let sign = private_key.sign(padding, &data[..]).unwrap();

    let padding = PaddingScheme::new_pkcs1v15_sign(Option::None);
    public_key.verify(padding, &data[..], &sign).unwrap();

    println!("sign test done")
}
