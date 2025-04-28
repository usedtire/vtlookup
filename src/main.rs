use std::env;
use std::error::Error;
use std::fs::File;
use std::process;
use csv::ReaderBuilder;
use reqwest::blocking::Client;
use serde_json::Value;

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {}", err);
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("Usage: cargo run <file.csv> <VirusTotal-API-Key>".into());
    }
    let file_path = &args[1];
    let api_key = &args[2];

    let file = File::open(file_path)?;
    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(file);

    let client = Client::new();

    for result in rdr.records() {
        let record = result?;
        if let Some(field) = record.get(8) {
            for part in field.split_whitespace() {
                // Directly use the SHA256 hash
                query_virustotal(&client, api_key, part)?;
            }
        } else {
            println!("(no ninth entry)");
        }
    }

    Ok(())
}

fn query_virustotal(client: &Client, api_key: &str, hash: &str) -> Result<(), Box<dyn Error>> {
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);

    let resp = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()?;

    if resp.status().is_success() {
        let json: Value = resp.json()?;
        println!("Response for hash {}: {:#}", hash, json);
    } else {
        println!("Failed to query hash {}: {}", hash, resp.status());
    }

    Ok(())
}
