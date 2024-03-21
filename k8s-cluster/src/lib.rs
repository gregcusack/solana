use {
    lazy_static::lazy_static,
    std::{env, path::PathBuf},
};

lazy_static! {
    #[derive(Debug)]
    static ref SOLANA_ROOT: PathBuf = get_solana_root();
}

#[macro_export]
macro_rules! boxed_error {
    ($message:expr) => {
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, $message)) as Box<dyn Error + Send>
    };
}

pub fn initialize_globals() {
    let _ = *SOLANA_ROOT; // Force initialization of lazy_static
}

pub fn get_solana_root() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get Solana root directory")
        .to_path_buf()
}

pub mod kubernetes;
pub mod release;
