use std::env;
use std::path::Path;
use std::path::PathBuf;

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
