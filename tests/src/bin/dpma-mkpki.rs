//! `dpma-mkpki`: makes the test PKI for the phone simulator and installs
//! its trust material into an instance (see `dpma_tests::mkpki`).
//!
//! ```text
//! dpma-mkpki                 generate (keeping existing files) and install
//! dpma-mkpki --force         regenerate everything
//! dpma-mkpki --no-install    generate only
//! dpma-mkpki --check         verify every certificate with `openssl verify`
//! ```
//!
//! The instance is `--instance DIR`, else the slot of `--slot N` or
//! `$DPMA_SLOT` (as `ast.sh info` describes it).

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::Parser;
use dpma_tests::harness::Instance;
use dpma_tests::{mkpki, sim};

#[derive(Parser)]
#[command(
    name = "dpma-mkpki",
    about = "Generate the test PKI for the DPMA phone simulator."
)]
struct Args {
    /// PKI directory (default: $DPMA_PKI, else dev/sim/pki, shared with the Python tools).
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Regenerate existing files.
    #[arg(long)]
    force: bool,
    /// MAC used in the subject names.
    #[arg(long, default_value = sim::DEFAULT_MAC)]
    mac: String,
    /// Instance slot (default: $DPMA_SLOT).
    #[arg(long)]
    slot: Option<u32>,
    /// Instance directory (overrides --slot).
    #[arg(long)]
    instance: Option<PathBuf>,
    /// Do not install into an instance.
    #[arg(long)]
    no_install: bool,
    /// Verify the certificates with openssl and exit.
    #[arg(long)]
    check: bool,
}

fn run(a: Args) -> Result<bool> {
    let dir = a.dir.unwrap_or_else(sim::default_pki_dir);
    let dir = std::path::absolute(&dir)?;
    if a.check {
        return Ok(mkpki::check(&dir)? == 0);
    }
    mkpki::Generator::new(&dir)
        .force(a.force)
        .mac(&a.mac)
        .generate()?;
    if a.no_install {
        return Ok(true);
    }
    let etc = match (a.instance, a.slot) {
        (Some(i), _) => i.join("etc").join("asterisk"),
        (None, Some(s)) => Instance::for_slot(s)?.etc,
        (None, None) => match std::env::var("DPMA_SLOT") {
            Ok(_) => Instance::from_env()?.etc,
            Err(_) => {
                bail!("no instance: give --slot, --instance, or $DPMA_SLOT (or --no-install)")
            }
        },
    };
    mkpki::install(&dir, &etc, false)?;
    Ok(true)
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("dpma-mkpki: {e:#}");
            ExitCode::FAILURE
        }
    }
}
