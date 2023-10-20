use {
    bzip2::bufread::BzDecoder,
    console::Emoji,
    indicatif::{ProgressBar, ProgressStyle},
    lazy_static::lazy_static,
    log::*,
    rsa::{
        RsaPrivateKey, 
        RsaPublicKey, 
        pkcs1::{
            EncodeRsaPrivateKey, 
            EncodeRsaPublicKey, 
            LineEnding
        }
    },
    std::{
        env,
        fs::{self, File},
        io::{self, BufRead, BufReader, Cursor, Read, Write},
        path::{Path, PathBuf},
        process::Stdio,
        time::Duration,
    },
    tar::Archive,
    url::Url,
};

lazy_static! {
    #[derive(Debug)]
    static ref SOLANA_ROOT: PathBuf = get_solana_root();

    #[derive(Debug)]
    pub static ref LEDGER_DIR: PathBuf = SOLANA_ROOT.join("config-k8s/bootstrap-validator");
}

pub fn initialize_globals() {
    let _ = *SOLANA_ROOT; // Force initialization of lazy_static
}

pub mod docker;
pub mod genesis;
pub mod kubernetes;
pub mod ledger_helper;
pub mod release;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ValidatorType {
    Bootstrap,
    Standard,
}

impl std::fmt::Display for ValidatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ValidatorType::Bootstrap => write!(f, "bootstrap"),
            ValidatorType::Standard => write!(f, "validator"),
        }
    }
}

pub fn get_solana_root() -> PathBuf {
    let solana_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get Solana root directory")
        .to_path_buf();
    info!("solana root: {:?}", solana_root);
    solana_root
}

#[macro_export]
macro_rules! boxed_error {
    ($message:expr) => {
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, $message)) as Box<dyn std::error::Error>
    };
}

static TRUCK: Emoji = Emoji("🚚 ", "");
static PACKAGE: Emoji = Emoji("📦 ", "");

/// Creates a new process bar for processing that will take an unknown amount of time
pub fn new_spinner_progress_bar() -> ProgressBar {
    let progress_bar = ProgressBar::new(42);
    progress_bar.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {wide_msg}")
            .expect("ProgresStyle::template direct input to be correct"),
    );
    progress_bar.enable_steady_tick(Duration::from_millis(100));
    progress_bar
}

pub fn extract_release_archive(
    archive: &Path,
    extract_dir: &Path,
    file_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let progress_bar = new_spinner_progress_bar();
    progress_bar.set_message(format!("{PACKAGE}Extracting..."));

    if extract_dir.exists() {
        fs::remove_dir_all(extract_dir)?;
    }
    fs::create_dir_all(extract_dir)?;

    let tmp_extract_dir = extract_dir.with_file_name("tmp-extract");

    if tmp_extract_dir.exists() {
        let _ = fs::remove_dir_all(&tmp_extract_dir);
    }
    fs::create_dir_all(&tmp_extract_dir)?;

    let tar_bz2 = File::open(archive)?;
    let tar = BzDecoder::new(BufReader::new(tar_bz2));
    let mut release = Archive::new(tar);
    release.unpack(&tmp_extract_dir)?;

    for entry in tmp_extract_dir.join(file_name).read_dir()? {
        let entry = entry?;
        let entry_path = entry.path();
        let target_entry_path = extract_dir.join(entry_path.file_name().unwrap());
        fs::rename(entry_path, target_entry_path)?;
    }

    // Remove the tmp-extract directory
    fs::remove_dir_all(tmp_extract_dir)?;
    progress_bar.finish_and_clear();
    Ok(())
}

pub async fn download_to_temp(
    url: &str,
    file_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let progress_bar = new_spinner_progress_bar();
    progress_bar.set_message(format!("{TRUCK}Downloading..."));

    let url = Url::parse(url).map_err(|err| format!("Unable to parse {url}: {err}"))?;

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .build()?;

    let response = client.get(url.as_str()).send().await?;
    // let file_name: PathBuf = SOLANA_ROOT.join("solana-release.tar.bz2");
    let file_name: PathBuf = SOLANA_ROOT.join(file_name);
    let mut out = File::create(file_name).expect("failed to create file");
    let mut content = Cursor::new(response.bytes().await?);
    std::io::copy(&mut content, &mut out)?;

    progress_bar.finish_and_clear();
    Ok(())
}

pub fn cat_file(path: &PathBuf) -> io::Result<()> {
    let mut file = fs::File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    info!("{}", contents);

    Ok(())
}


// pub fn generate_ssh_key(outfile_name: &str) -> Result<(), Box<dyn std::error::Error>> {
//     let output_dir = SOLANA_ROOT.join("config-k8s");

//     let mut rng = rand::thread_rng();
//     let private_key = RsaPrivateKey::new(&mut rng, 512)?;
//     let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
//     let private_key_file_path: PathBuf = output_dir.join(outfile_name); //id_rsa_i
//     let mut private_key_file = File::create(private_key_file_path)?;
//     private_key_file.write_all(&private_key_pem.as_bytes())?;

//     let public_key = RsaPublicKey::from(&private_key);
//     let public_key_pem = public_key.to_pkcs1_pem(LineEnding::LF)?;
//     let pubkey_file_path = output_dir.join(format!("{}.pub", outfile_name));
//     let mut pubkey_file = File::create(pubkey_file_path)?;
//     pubkey_file.write_all(&public_key_pem.as_bytes())?;

//     Ok(())
// }

pub fn generate_ssh_key(outfile_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = SOLANA_ROOT.join("config-k8s");

    let yes = std::process::Command::new("yes")
        .arg("")
        .stdout(Stdio::piped())
        .spawn()?;

    let yes_stdout = yes.stdout.unwrap();

    let _ = std::process::Command::new("ssh-keygen")
        .arg("-f")
        .arg(output_dir.join(outfile_name))
        .arg("-t")
        .arg("rsa")
        .arg("-b")
        .arg("1024")
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg(outfile_name)
        .stdin(Stdio::from(yes_stdout))
        .output()?;

    // let mut rng = rand::thread_rng();
    // let private_key = RsaPrivateKey::new(&mut rng, 512)?;
    // let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    // let private_key_file_path: PathBuf = output_dir.join(outfile_name); //id_rsa_i
    // let mut private_key_file = File::create(private_key_file_path)?;
    // private_key_file.write_all(&private_key_pem.as_bytes())?;

    // let public_key = RsaPublicKey::from(&private_key);
    // let public_key_pem = public_key.to_pkcs1_pem(LineEnding::LF)?;
    // let pubkey_file_path = output_dir.join(format!("{}.pub", outfile_name));
    // let mut pubkey_file = File::create(pubkey_file_path)?;
    // pubkey_file.write_all(&public_key_pem.as_bytes())?;

    Ok(())
}

pub fn append_pubkeys_to_authorized_keys(
    num_files: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    let outfile_path: PathBuf = SOLANA_ROOT.join("config-k8s/authorized_keys");
    if Path::new(&outfile_path).exists() {
        std::fs::remove_file(&outfile_path)?;
    }

    let mut outfile = File::create(&outfile_path)?;

    for i in 0..num_files {
        let filename = SOLANA_ROOT.join(format!("config-k8s/id_rsa_{}.pub", i));
        
        let file = File::open(&filename)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            writeln!(outfile, "{}", line?)?;
        }
    }
    Ok(())
}