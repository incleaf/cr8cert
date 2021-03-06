extern crate clap;

mod cert;

use std::fs;
use clap::{App, Arg};
use std::fs::File;


fn main() {
    let matches = App::new("cr8cert")
        .about("A simple zero-config tool to make locally trusted development certificates with any names you'd like.")
        .version("1.0")
        .author("Hyeonsu Lee <incleaf@gmail.com>")
        .arg(Arg::with_name("install")
            .help("Install the local CA in the system trust store.")
            .short("i")
            .long("install"))
        .arg(Arg::with_name("uninstall")
            .help("Uninstall the local CA in the system trust store.")
            .short("u")
            .long("uninstall"))
        .arg(Arg::with_name("create")
            .multiple(true)
            .takes_value(true)
            .help("Create a certificate with the given names")
            .short("c")
            .long("create"))
        .get_matches();

    if matches.is_present("debug") {
        println!("Debugging is turned on");
    }

    if matches.is_present("install") {
        let ca_root = cert::get_ca_root();
        fs::create_dir_all(&ca_root).expect("Failed create a CA root directory");

        let root_ca_path = ca_root.join(cert::ROOT_NAME);
        let root_ca_key_path = ca_root.join(cert::KEY_NAME);

        if !root_ca_path.exists() || !root_ca_key_path.exists() {
            let (ca_cert, ca_privkey) = cert::generate_ca().expect("Failed to generate CA");
            let ca_pem = ca_cert.to_pem().expect("Failed to serialize the certificate into a PEM-encoded X509 structure");
            let priv_der = ca_privkey.private_key_to_pem_pkcs8().expect("Failed to serialized the private key to PEM");

            fs::write(root_ca_path, ca_pem).expect("Failed to write a certificate file");
            fs::write(root_ca_key_path, priv_der).expect("Failed to write a key file");

            cert::install_to_trust_store().expect("Failed to intall to trust store");

            println!("✨ Created a new local CA at {:?}", ca_root.to_str().unwrap());
        } else {
            println!("✨ Local CA already installed at {:?}", ca_root.to_str().unwrap());
        };
    }

    if matches.is_present("uninstall") {
        cert::uninstall_from_trust_store().expect("Failed to uninstall the local CA from trust store");
        println!("✨ Local CA successfully uninstalled");
    }

    if let Some(_) = matches.values_of("create") {
        let hosts: Vec<_> = matches.values_of("create").unwrap().collect();

        let ca_root = cert::get_ca_root();
        fs::create_dir_all(&ca_root).expect("Failed create a CA root directory");

        let root_ca_path = ca_root.join(cert::ROOT_NAME);
        let root_ca_key_path = ca_root.join(cert::KEY_NAME);

        let root_ca = File::open(root_ca_path).expect("Local CA is not installed. You can install it with --install flag.");
        let root_ca_key = File::open(root_ca_key_path).expect("Local CA is not installed. You can install it with --install flag.");

        cert::cr8cert(hosts, root_ca, root_ca_key).ok();
    }
}
