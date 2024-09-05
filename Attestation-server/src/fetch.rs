use super::*;

use core::fmt;

use std::{fs, path::{Path,PathBuf}, str::FromStr};

use sev::firmware::host::CertType;
use sev::{
    certs::snp::{Certificate},
};

use certs::{write_cert, CertFormat};

use sev::firmware::guest::{AttestationReport};

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum Endorsement {
    /// Versioned Chip Endorsement Key
    Vcek,

    /// Versioned Loaded Endorsement Key
    Vlek,
}

impl fmt::Display for Endorsement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endorsement::Vcek => write!(f, "VCEK"),
            Endorsement::Vlek => write!(f, "VLEK"),
        }
    }
}

impl FromStr for Endorsement {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "vcek" => Ok(Self::Vcek),
            "vlek" => Ok(Self::Vlek),
            _ => Err(anyhow::anyhow!("Endorsement type not found!")),
        }
    }
}
#[derive(ValueEnum, Debug, Clone)]
pub enum ProcType {
    /// 3rd Gen AMD EPYC Processor (Standard)
    Milan,

    /// 4th Gen AMD EPYC Processor (Standard)
    Genoa,

    /// 4th Gen AMD EPYC Processor (Performance)
    Bergamo,

    /// 4th Gen AMD EPYC Processor (Edge)
    Siena,
}

impl ProcType {
    fn to_kds_url(&self) -> String {
        match self {
            ProcType::Genoa | ProcType::Siena | ProcType::Bergamo => &ProcType::Genoa,
            _ => self,
        }
        .to_string()
    }
}

impl FromStr for ProcType {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<ProcType, anyhow::Error> {
        match input.to_lowercase().as_str() {
            "milan" => Ok(ProcType::Milan),
            "genoa" => Ok(ProcType::Genoa),
            "bergamo" => Ok(ProcType::Bergamo),
            "siena" => Ok(ProcType::Siena),
            _ => Err(anyhow::anyhow!("Processor type not found!")),
        }
    }
}

impl fmt::Display for ProcType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcType::Milan => write!(f, "Milan"),
            ProcType::Genoa => write!(f, "Genoa"),
            ProcType::Bergamo => write!(f, "Bergamo"),
            ProcType::Siena => write!(f, "Siena"),
        }
    }
}

pub mod cert_authority {
    use super::*;
    use openssl::x509::X509;
    use reqwest::StatusCode;

    // Function to build kds request for ca chain and return a vector with the 2 certs (ASK & ARK)
    pub async fn request_ca_kds(
        processor_model: ProcType,
        endorser: &Endorsement,
    ) -> Result<Vec<X509>, anyhow::Error> {
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_CERT_CHAIN: &str = "cert_chain";
        
        // Should make -> https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/cert_chain
        let url: String = format!(
            "{KDS_CERT_SITE}/{}/v1/{}/{KDS_CERT_CHAIN}",
            endorser.to_string().to_lowercase(),
            processor_model.to_kds_url()
        );

        let rsp = reqwest::get(url).await?;   //context("Unable to send request for certs to URL")?;

        match rsp.status() {
            StatusCode::OK => {
                // Parse the request
                let body = rsp
                    .bytes().await?
                    .to_vec();

                let certificates = X509::stack_from_pem(&body)?;

                Ok(certificates)
            }
            status => Err(anyhow::anyhow!("Unable to fetch certificate: {:?}", status)),
        }
    }

    // Fetch the ca from the kds and write it into the certs directory
    pub async fn fetch_ca(proc_type: ProcType, endorser: Endorsement, certs_dir: PathBuf) -> Result<()> {
        // Get certs from kds
        let certificates = request_ca_kds(proc_type, &endorser).await?;

        // Create certs directory if missing
        if !certs_dir.exists() {
            fs::create_dir(certs_dir.as_path()).context("Could not create certs folder")?;
        }

        let ark_cert = &certificates[1];
        let ask_cert = &certificates[0];

        write_cert(
            certs_dir.as_path(),
            &CertType::ARK,
            &ark_cert.to_pem()?,
            CertFormat::Pem,
            &endorser,
        )?;
        write_cert(
            certs_dir.as_path(),
            &CertType::ASK,
            &ask_cert.to_pem()?,
            CertFormat::Pem,
            &endorser,
        )?;

        Ok(())
    }
}

pub mod vcek {
    use reqwest::StatusCode;

    use super::*;

    #[derive(Parser)]
    pub struct Args {
        /// Specify encoding to use for certificates.
        #[arg(value_name = "encoding", required = true)]
        pub encoding: CertFormat,

        /// Specify the processor model for the certificate chain.
        #[arg(value_name = "processor-model", required = true)]
        pub processor_model: ProcType,

        /// Directory to store the certificates in.
        #[arg(value_name = "certs-dir", required = true)]
        pub certs_dir: PathBuf,

        /// Path to attestation report to use to request VCEK.
        #[arg(value_name = "att-report-path", required = true)]
        pub att_report_path: PathBuf,
    }

    // Function to request vcek from KDS. Return vcek in der format.
    pub async fn request_vcek_kds(
        processor_model: ProcType,
        att_report: AttestationReport,
    ) -> Result<Vec<u8>, anyhow::Error> {
        // KDS URL parameters
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";

        // Use attestation report to get data for URL
        let hw_id: String = hex::encode(att_report.chip_id);
        
        let vcek_url: String = format!(
            "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
            {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            processor_model.to_kds_url(),
            att_report.reported_tcb.bootloader,
            att_report.reported_tcb.tee,
            att_report.reported_tcb.snp,
            att_report.reported_tcb.microcode
        );

        // VCEK in DER format
        let vcek_rsp = reqwest::get(vcek_url).await?; //.context("Unable to send request for VCEK")?;

        match vcek_rsp.status() {
            StatusCode::OK => {
                let vcek_rsp_bytes: Vec<u8> =
                    vcek_rsp.bytes().await?.to_vec();
                Ok(vcek_rsp_bytes)
            }
            status => Err(anyhow::anyhow!("Unable to fetch VCEK from URL: {status:?}")),
        }
    }

    // Function to request vcek from kds and write it into file
    pub async fn fetch_vcek(processor_model: ProcType,
        att_report_path: AttestationReport, _certs_dir: &Path) -> Result<Certificate> {
        // Request vcek
        let vcek: Vec<u8> = request_vcek_kds(processor_model, att_report_path).await?;
        
        let cert: Certificate = Certificate::from_bytes(&vcek)?;

        Ok(cert)
    }
}
#[cfg(test)]
mod tests {
    use super::ProcType;

    #[test]
    fn test_kds_prod_name_milan_base() {
        let milan_proc: ProcType = ProcType::Milan;
        assert_eq!(milan_proc.to_kds_url(), ProcType::Milan.to_string());
    }

    #[test]
    fn test_kds_prod_name_genoa_base() {
        assert_eq!(ProcType::Genoa.to_kds_url(), ProcType::Genoa.to_string());
        assert_eq!(ProcType::Siena.to_kds_url(), ProcType::Genoa.to_string());
        assert_eq!(ProcType::Bergamo.to_kds_url(), ProcType::Genoa.to_string());
    }
}