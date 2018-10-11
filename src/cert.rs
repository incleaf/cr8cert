extern crate openssl;
extern crate pem;

use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;
use std::fs;

use cert::openssl::rsa::Rsa;
use cert::openssl::x509::{X509, X509NameBuilder};
use cert::openssl::asn1::Asn1Time;
use cert::openssl::bn::{BigNum,MsbOption};
use cert::openssl::error::ErrorStack;
use cert::openssl::hash::MessageDigest;
use cert::openssl::pkey::{PKey, Private};
use cert::openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage,
                               SubjectAlternativeName, SubjectKeyIdentifier, ExtendedKeyUsage};
use std::net::IpAddr;
use std::process::Command;
use std::str;

pub const ROOT_NAME: &'static str = "rootCA.pem";
pub const KEY_NAME: &'static str = "rootCA-key.pem";


const MSB_MAYBE_ZERO: MsbOption = MsbOption::MAYBE_ZERO;

pub fn get_ca_root() -> PathBuf {
  let path = env::var("ROOTCA").unwrap_or_default();

  if !path.is_empty() {
    return Path::new(&path).to_owned();
  };

  // TODO: Get base dir of each OS
  let home = env::var("HOME").unwrap_or_default();
  let homepath = Path::new(&home);
  return homepath.join("Library/Application Support/cr8cert").to_owned();
}

pub fn generate_ca() -> Result<(X509, PKey<Private>), ErrorStack> {
  let rsa = Rsa::generate(3072)?;
  let privkey = PKey::from_rsa(rsa)?;

  let mut x509_name = X509NameBuilder::new()?;
  x509_name.append_entry_by_text("O", "cr8cert develpoment CA")?;
  x509_name.append_entry_by_text("OU", "cr8cert")?;
  let x509_name = x509_name.build();

  let mut cert_builder = X509::builder()?;
  cert_builder.set_version(2)?;
  let serial_number = {
      let mut serial = BigNum::new()?;
      serial.rand(159, MSB_MAYBE_ZERO, false)?;
      serial.to_asn1_integer()?
  };
  cert_builder.set_serial_number(&serial_number)?;
  cert_builder.set_subject_name(&x509_name)?;
  cert_builder.set_issuer_name(&x509_name)?;
  cert_builder.set_pubkey(&privkey)?;
  let not_before = Asn1Time::days_from_now(0)?;
  cert_builder.set_not_before(&not_before)?;
  let not_after = Asn1Time::days_from_now(365)?;
  cert_builder.set_not_after(&not_after)?;

  cert_builder.append_extension(BasicConstraints::new().critical()
    .ca().pathlen(0).build()?)?;
  cert_builder.append_extension(KeyUsage::new()
      .critical()
      .key_cert_sign()
      .build()?)?;

  let subject_key_identifier =
      SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
  cert_builder.append_extension(subject_key_identifier)?;

  cert_builder.sign(&privkey, MessageDigest::sha256())?;
  let cert = cert_builder.build();

  Ok((cert, privkey))
}

pub fn cr8cert(hosts: Vec<&str>, mut ca: File, mut ca_key: File) -> Result<(X509, PKey<Private>), ErrorStack> {
  println!("Hosts detected: {:?}", hosts);

  let mut buffer = String::new();
  ca.read_to_string(&mut buffer).unwrap();
  let ca = X509::from_pem(&buffer.into_bytes()).unwrap();

  let mut buffer = String::new();
  ca_key.read_to_string(&mut buffer).unwrap();
  let pkey = PKey::private_key_from_pem(&buffer.into_bytes()).unwrap();

  let rsa = Rsa::generate(2048)?;
  let privkey = PKey::from_rsa(rsa)?;

  let mut x509_name = X509NameBuilder::new()?;
  x509_name.append_entry_by_text("O", "cr8cert development Certificate")?;
  x509_name.append_entry_by_text("CN", "cr8cert")?;
  let x509_name = x509_name.build();

  let mut cert_builder = X509::builder()?;
  cert_builder.set_version(2)?;
  let serial_number = {
      let mut serial = BigNum::new()?;
      serial.rand(159, MSB_MAYBE_ZERO, false)?;
      serial.to_asn1_integer()?
  };
  cert_builder.set_serial_number(&serial_number)?;
  cert_builder.set_subject_name(&x509_name)?;
  cert_builder.set_issuer_name(&ca.subject_name())?;
  cert_builder.set_pubkey(&privkey)?;
  let not_before = Asn1Time::days_from_now(0)?;
  cert_builder.set_not_before(&not_before)?;
  let not_after = Asn1Time::days_from_now(365)?;
  cert_builder.set_not_after(&not_after)?;

  cert_builder.append_extension(BasicConstraints::new()
    .critical()
    .build()?)?;
  cert_builder.append_extension(KeyUsage::new()
    .critical()
    .digital_signature()
    .key_encipherment()
    .build()?)?;

  let mut san_builder = SubjectAlternativeName::new();
  for san in hosts {
    let is_ip = san.parse::<IpAddr>().is_ok();
    if is_ip {
        san_builder.ip(san);
    } else {
        san_builder.dns(san);
    }
  }
  let sans = san_builder.build(&cert_builder.x509v3_context(Some(&ca), None))?;
  cert_builder.append_extension(sans)?;

  let auth_key_identifier = AuthorityKeyIdentifier::new()
      .keyid(true)
      .build(&cert_builder.x509v3_context(Some(&ca), None))?;
  cert_builder.append_extension(auth_key_identifier)?;

  cert_builder.append_extension(ExtendedKeyUsage::new()
  .server_auth().build()?)?;


  cert_builder.sign(&pkey, MessageDigest::sha256())?;
  let cert = cert_builder.build();

  let ca_pem = cert.to_pem().expect("Failed to serialize the certificate into a PEM-encoded X509 structure");
  let priv_pem = privkey.private_key_to_pem_pkcs8().expect("Failed to serialized the private key to PEM");

  fs::write(env::current_dir().unwrap().join("cert.pem"), ca_pem).expect("Failed to write a certificate file");
  fs::write(env::current_dir().unwrap().join("key.pem"), priv_pem).expect("Failed to write a key file");

  return Ok((cert, pkey));
}

pub fn install_to_trust_store() -> Result<(), ()> {
  let ca_root = get_ca_root();
  let output = Command::new("sudo")
    .arg("security")
    .arg("add-trusted-cert")
    .arg("-d")
    .arg("-k")
    .arg("/Library/Keychains/System.keychain")
    .arg(ca_root.join(ROOT_NAME))
    .output()
    .expect("failed to execute process");

  if !output.status.success() {
    let s = match str::from_utf8(&output.stderr) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    panic!("{}", s);
  };

  let tmp_filename = String::from("tmp");
  File::create(&tmp_filename).expect("Failed to create a temp file");
  Command::new("sudo").arg("security").arg("trust-settings-export").arg("-d").arg(&tmp_filename).output().expect("failed to execute process");
  Ok(())
}

pub fn uninstall_from_trust_store() -> Result<(), ()> {
  let ca_root = get_ca_root();
  let output = Command::new("sudo")
    .arg("security")
    .arg("remove-trusted-cert")
    .arg("-d")
    .arg(ca_root.join(ROOT_NAME))
    .output()
    .expect("failed to execute process");

  if !output.status.success() {
    let s = match str::from_utf8(&output.stderr) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    panic!("{}", s);
  };

  fs::remove_dir_all(&ca_root).expect("Failed delete the CA root directory");

  Ok(())
}