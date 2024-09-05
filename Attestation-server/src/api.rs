use serde::{Deserialize, Serialize};
use axum::{extract::Json, response::{Response}, http::StatusCode};
use sev::firmware::guest::AttestationReport;

use crate::verify;


#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
}

/// Root endpoint 
pub async fn root() -> Json<StatusResponse> {
    let status = StatusResponse{
        status: "Axilr Attestation server for AMD SEV-SNP".to_string()
    };
    axum::Json(status)
}

#[derive(Serialize, Deserialize)]
pub struct ReportResponse {
    cert: Vec<u8>, 
    report: AttestationReport, 
    miner_ip: String, 
}

/// Verify endpoint
pub async fn verify_report(reportresp: Json<ReportResponse>, measurement: String) -> Response {
    let report: AttestationReport = reportresp.report;
    let cert = reportresp.cert.clone();
    let miner_ip = reportresp.miner_ip.clone();
    let status = verify::cmd(report, cert, miner_ip, measurement, true).await;
    match status {
        Ok(_) => {
            Response::new("OK".into())
        },    
        Err(_) => {
            let response = Response::new("Failed to verify attestation report!".into());
            let (mut parts, body) = response.into_parts();
            parts.status = StatusCode::BAD_REQUEST;
            let response = Response::from_parts(parts, body);
            response
        },
    }
}
