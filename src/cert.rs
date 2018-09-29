extern crate openssl;
extern crate pem;

use std::env;
use std::path::Path;
use std::path::PathBuf;

use cert::openssl::rsa::Rsa;
use cert::openssl::x509::{X509, X509NameBuilder, X509Ref};
use cert::openssl::asn1::{Asn1BitStringRef, Asn1IntegerRef, Asn1ObjectRef, Asn1StringRef, Asn1TimeRef};
use cert::openssl::asn1::Asn1Time;
use cert::openssl::bn::{BigNum,MsbOption};
use cert::openssl::error::ErrorStack;
use cert::openssl::hash::MessageDigest;
use cert::openssl::pkey::{PKey, PKeyRef, Private};
use cert::openssl::x509::{X509Req, X509ReqBuilder};
use cert::openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage,
                               SubjectAlternativeName, SubjectKeyIdentifier};
use cert::pem::{Pem, encode};

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
  let rsa = Rsa::generate(2048)?;
  let privkey = PKey::from_rsa(rsa)?;

  let mut x509_name = X509NameBuilder::new()?;
  x509_name.append_entry_by_text("C", "US")?;
  x509_name.append_entry_by_text("ST", "TX")?;
  x509_name.append_entry_by_text("O", "Some CA organization")?;
  x509_name.append_entry_by_text("CN", "ca test")?;
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

  cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
  cert_builder.append_extension(KeyUsage::new()
      .critical()
      .key_cert_sign()
      .crl_sign()
      .build()?)?;

  let subject_key_identifier =
      SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
  cert_builder.append_extension(subject_key_identifier)?;

  cert_builder.sign(&privkey, MessageDigest::sha256())?;
  let cert = cert_builder.build();

  Ok((cert, privkey))
}