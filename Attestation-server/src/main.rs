mod certs;
mod fetch;
mod verify;
mod api;

use std::fs::File;

use anyhow::{Context, Result};
use clap::{arg, Parser, ValueEnum};

use axum::{
    routing::{get,post}, 
    Router, Json
};
use serde_json;
use tokio;
use api::{verify_report,root,ReportResponse};



#[tokio::main]
async fn main() -> Result<(),anyhow::Error> {
    let measurement_file = File::open("measurement.json")?;
    let measurement_json: serde_json::Value = serde_json::from_reader(measurement_file).expect("Failed to parse measurement from file");
    //Double str conversion because .to_string is not supported natively by serde_json and causes an inclusion of the json quotes in the string
    let measurement: String = measurement_json.get("measurement").expect("Missing measurement").as_str().expect("failed to parse measurement").to_string();

    let app = Router::new().route("/check", get(root)).route("/report", post(move |body: Json<ReportResponse>|{
        verify_report(body, measurement)})).with_state(());
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("Starting http server at : 0.0.0.0:8080");
    
    Ok(axum::serve(listener, app).await.unwrap())

}