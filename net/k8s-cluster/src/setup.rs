use {
    super::initialize_globals,
    bzip2::bufread::BzDecoder,
    console::{style, Emoji},
    indicatif::{ProgressBar, ProgressStyle},
    log::*,
    reqwest::{self, Response},
    solana_sdk::hash::{Hash, Hasher},
    std::{
        fs,
        fs::File,
        io::{self, BufReader, Cursor, Read},
        path::{Path, PathBuf},
        time::Duration,
    },
    tar::Archive,
    tempfile::TempDir,
    url::Url,
};

#[derive(Clone, Debug)]
pub struct DeployConfig<'a> {
    pub release_channel: &'a str,
    pub deploy_method: &'a str,
    pub do_build: bool,
}

#[derive(Clone, Debug)]
pub struct Deploy<'a> {
    config: DeployConfig<'a>,
}

static TRUCK: Emoji = Emoji("🚚 ", "");
static PACKAGE: Emoji = Emoji("📦 ", "");

/// Creates a new process bar for processing that will take an unknown amount of time
fn new_spinner_progress_bar() -> ProgressBar {
    let progress_bar = ProgressBar::new(42);
    progress_bar.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {wide_msg}")
            .expect("ProgresStyle::template direct input to be correct"),
    );
    progress_bar.enable_steady_tick(Duration::from_millis(100));
    progress_bar
}

fn extract_release_archive(
    archive: &Path,
    extract_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let progress_bar = new_spinner_progress_bar();
    progress_bar.set_message(format!("{PACKAGE}Extracting..."));

    if extract_dir.exists() {
        fs::remove_dir_all(&extract_dir)?;
    }
    fs::create_dir_all(&extract_dir)?;

    let tmp_extract_dir = extract_dir.with_file_name("tmp-extract");

    if tmp_extract_dir.exists() {
        let _ = fs::remove_dir_all(&tmp_extract_dir);
    }
    fs::create_dir_all(&tmp_extract_dir)?;

    let tar_bz2 = File::open(archive)?;
    let tar = BzDecoder::new(BufReader::new(tar_bz2));
    let mut release = Archive::new(tar);
    release.unpack(&tmp_extract_dir)?;

    for entry in tmp_extract_dir.join("solana-release/").read_dir()? {
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

async fn download_to_temp(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let progress_bar = new_spinner_progress_bar();
    progress_bar.set_message(format!("{TRUCK}Downloading..."));

    let url = Url::parse(url).map_err(|err| format!("Unable to parse {url}: {err}"))?;

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .build()?;

    let response = client.get(url.as_str()).send().await?;
    let file_name: PathBuf = super::SOLANA_ROOT.join("solana-release.tar.bz2");
    let mut out = File::create(file_name).expect("failed to create file");
    let mut content = Cursor::new(response.bytes().await?);
    std::io::copy(&mut content, &mut out)?;

    progress_bar.finish_and_clear();
    Ok(())
}

fn cat_file(path: &PathBuf) -> io::Result<()> {
    let mut file = fs::File::open(&path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    info!("{}", contents);

    Ok(())
}


impl<'a> Deploy<'a> {
    pub fn new(config: DeployConfig<'a>) -> Self {
        initialize_globals();
        Deploy { config }
    }

    pub async fn prepare(&self) {
        match self.config.deploy_method {
            "tar" => {
                match self.setup_tar_deploy().await {
                    Ok(tar_directory) => {
                        info!("Sucessfuly setup tar file");
                        cat_file(&tar_directory.join("version.yml")).unwrap();
                    },
                    Err(_) => error!("Failed to setup tar file!"),
                }
            }
            "local" => self.setup_local_deploy(),
            "skip" => (),
            _ => error!(
                "Internal error: Invalid deploy_method: {}",
                self.config.deploy_method
            ),
        }
    }

    async fn setup_tar_deploy(&self) -> Result<(PathBuf), String> {
        info!("tar file deploy");
        if !self.config.release_channel.is_empty() {
            match self.download_release_from_channel().await {
                Ok(_) => info!("Successfully downloaded tar release from channel"),
                Err(_) => error!("Failed to download tar release"),
            }
        }

        // Extract it and load the release version metadata
        let tarball_filename = super::SOLANA_ROOT.join("solana-release.tar.bz2");
        let temp_release_dir = super::SOLANA_ROOT.join("solana-release/");
        extract_release_archive(&tarball_filename, &temp_release_dir).map_err(|err| {
            format!("Unable to extract {tarball_filename:?} into {temp_release_dir:?}: {err}")
        })?;

        Ok((temp_release_dir))
    }

    fn setup_local_deploy(&self) {
        info!("local deploy");
        if self.config.do_build {
            info!("call build()");
            self.build();
        } else {
            info!("Build skipped due to --no-build");
        }
    }

    fn build(&self) {
        info!("building!");
    }

    async fn download_release_from_channel(&self) -> Result<(), String> {
        info!(
            "Downloading release from channel: {}",
            self.config.release_channel
        );
        let file_path = super::SOLANA_ROOT.join("solana-release.tar.bz2");
        // Remove file
        if let Err(err) = fs::remove_file(&file_path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                error!("Error while removing file: {:?}", err);
            }
        }

        let update_download_url = format!(
            "{}{}{}",
            "https://release.solana.com/",
            self.config.release_channel,
            "/solana-release-x86_64-unknown-linux-gnu.tar.bz2"
        );
        info!("update_download_url: {}", update_download_url);

        let _ = download_to_temp(update_download_url.as_str())
            .await
            .map_err(|err| format!("Unable to download {update_download_url}: {err}"))?;

        Ok(())
    }

    // async
}
