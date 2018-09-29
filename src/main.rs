extern crate clap;

mod cert;

use std::fs;
use clap::{App, Arg};

const rootName: &'static str = "rootCA.pem";
const keyName: &'static str = "rootCA-key.pem";

fn main() {
    let matches = App::new("cr8cert")
                        .about("A simple zero-config tool to make locally trusted development certificates with any names you'd like.")
                        .version("1.0")
                        .author("Hyeonsu Lee <incleaf@gmail.com>")
                        .arg(Arg::with_name("install")
                                    .help("Install the local CA in the system trust store.")
                                    .short("i")
                                    .long("install"))
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

    if let Some(_) = matches.values_of("create") {
        let names: Vec<_> = matches.values_of("create").unwrap().collect();
        println!("Names detected: {:?}", names);
    }

    let ca_root = cert::get_ca_root();
    fs::create_dir_all(ca_root).ok();
}
