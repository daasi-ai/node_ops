use crate::fetch::Endorsement;

use super::*;

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use sev::{
    certs::snp::{ca, Certificate},
    firmware::{host::CertType},
};

pub struct CertPaths {
    pub ark_path: PathBuf,
    pub ask_path: PathBuf,
}

#[derive(ValueEnum, Clone, Copy)]
pub enum CertFormat {
    /// Certificates are encoded in PEM format.
    Pem,

    /// Certificates are encoded in DER format.
    Der,
}

impl std::fmt::Display for CertFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertFormat::Pem => write!(f, "pem"),
            CertFormat::Der => write!(f, "der"),
        }
    }
}

impl FromStr for CertFormat {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<CertFormat, anyhow::Error> {
        match input.to_lowercase().as_str() {
            "pem" => Ok(CertFormat::Pem),
            "der" => Ok(CertFormat::Der),
            _ => Err(anyhow::anyhow!("Invalid Cert Format!")),
        }
    }
}

// Function that will convert a cert path into a snp Certificate
pub fn convert_path_to_cert(
    cert_path: &PathBuf,
    cert_type: &str,
) -> Result<Certificate, anyhow::Error> {
    let mut buf = vec![];

    let mut current_file = if cert_path.as_os_str().is_empty() {
        match fs::File::open(format!("./certs/{cert_type}.pem")) {
            Ok(file) => file,
            Err(err) => match err.kind() {
                ErrorKind::NotFound => match fs::File::open(format!("./certs/{cert_type}.der")) {
                    Ok(file) => file,
                    Err(e) => {
                        return Err(anyhow::anyhow!("Problem opening {cert_type} file {:?}", e))
                    }
                },
                other_error => {
                    return Err(anyhow::anyhow!(
                        "Problem opening {cert_type} file {:?}",
                        other_error
                    ));
                }
            },
        }
    } else {
        fs::File::open(cert_path).context(format!("Could not open provided {cert_type} file"))?
    };

    current_file
        .read_to_end(&mut buf)
        .context(format!("Could not read contents of {cert_type} file"))?;

    Ok(Certificate::from_bytes(&buf)?)
}

// Tryfrom function that takes in 3 certificate paths returns a snp Certificate Chain
impl TryFrom<CertPaths> for ca::Chain {
    type Error = anyhow::Error;
    fn try_from(content: CertPaths) -> Result<Self, Self::Error> {
        let ark_cert: Certificate = convert_path_to_cert(&content.ark_path, "ark")?;
        let ask_cert: Certificate = convert_path_to_cert(&content.ask_path, "ask")?;

        let ca_chain = ca::Chain {
            ark: ark_cert,
            ask: ask_cert,
        };

        Ok(ca_chain)
    }
}

// Function used to write provided cert into desired directory.
pub fn write_cert(
    path: &Path,
    cert_type: &CertType,
    data: &[u8],
    encoding: CertFormat,
    endorser: &Endorsement,
) -> Result<()> {
    // Get cert type into str
    let cert: Certificate = Certificate::from_bytes(data)?;

    let cert_str: String = match (cert_type, endorser) {
        (CertType::ASK, Endorsement::Vlek) => "asvk".to_string(),
        (_, _) => match cert_type {
            CertType::Empty => "empty".to_string(),
            CertType::ARK => "ark".to_string(),
            CertType::ASK => "ask".to_string(),
            CertType::VCEK => "vcek".to_string(),
            CertType::VLEK => "vlek".to_string(),
            CertType::CRL => "crl".to_string(),
            CertType::OTHER(uuid) => format!("other-{uuid}"),
        },
    };

    let bytes: Vec<u8> = match encoding {
        CertFormat::Pem => cert.to_pem()?,
        CertFormat::Der => cert.to_der()?,
    };

    let cert_path: PathBuf = path.join(format!("{cert_str}.{encoding}"));

    // Write cert into directory
    let mut file = if cert_path.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(cert_path)
            .context(format!("Unable to overwrite {cert_str} cert contents"))?
    } else {
        fs::File::create(cert_path).context(format!("Unable to create {cert_str} certificate"))?
    };

    file.write(&bytes)
        .context(format!("unable to write data to file {:?}", file))?;

    Ok(())
}

#[derive(Parser)]
pub struct CertificatesArgs {
    /// Specify encoding to use for certificates.
    #[arg(value_name = "encoding", required = true)]
    pub encoding: CertFormat,

    /// Directory to store certificates in. Required if requesting an extended-report.
    #[arg(value_name = "certs-dir", required = true)]
    pub certs_dir: PathBuf,
}
