use serde_json::Value;
use std::error::Error;
use std::fs;
use std::net::Ipv4Addr;
use tokio::time::{self, Duration};

use serde::Deserialize;

#[derive(Deserialize)]
struct Secrets {
    api_token: String,
    domain: String,
    record_name: String,
    auth_email: String,
    auth_key: String,
}

fn read_secrets_from_file(path: &str) -> Result<Secrets, Box<dyn Error>> {
    let data = fs::read_to_string(path)?;
    let secrets: Secrets = serde_json::from_str(&data)?;
    Ok(secrets)
}

#[tokio::main]
async fn main() {
    let mut interval = time::interval(Duration::from_secs(60)); // Run every 60 seconds
    let mut current_ip: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

    loop {
        interval.tick().await; // Wait for the next interval
        let public_ip = fetch_public_ip().await.unwrap();
        if current_ip != public_ip {
            println!("Detected new IP: {public_ip} - Old IP: {current_ip}");
            let res = update_ip_on_cloudflare(public_ip).await;
            match res {
                Ok(_) => println!("Worked!"),
                Err(error) => eprintln!("{:?}", error),
            }
            current_ip = public_ip;
        } else {
            println!("No new IP: {public_ip} - Old IP: {current_ip}");
        }
    }
}

async fn update_ip_on_cloudflare(new_ip: Ipv4Addr) -> Result<(), Box<dyn Error>> {
    let secrets = read_secrets_from_file("secrets.json").expect("Failed to read secrets");

    let client = reqwest::Client::new();

    let response = client
        .get(&format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            secrets.domain
        ))
        .header("Authorization", format!("Bearer {}", secrets.api_token))
        .send()
        .await?;

    let json: Value = response.json().await?;
    let zone_id = json["result"][0]["id"].as_str().unwrap().to_string();

    let response = client
        .get(&format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone_id
        ))
        .header("Authorization", format!("Bearer {}", secrets.api_token))
        .send()
        .await?;

    let json: Value = response.json().await?;
    let mut record_id = String::new();
    for record in json["result"].as_array().unwrap() {
        let name = record["name"].as_str().unwrap();
        if name == secrets.record_name {
            record_id = record["id"].as_str().unwrap().to_string();
        }
    }
    let client = reqwest::Client::new();
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
        zone_id, record_id
    );

    let body = serde_json::json!({
        "type": "A",
        "name": secrets.record_name, // Replace with your DNS record name
        "content": new_ip.to_string(),
        "ttl": 1, // Use automatic TTL
        "proxied": false,
    });

    let response = client
        .put(&url) // Using PUT since your example uses PUT
        .header("Content-Type", "application/json")
        .header("X-Auth-Email", secrets.auth_email) // Using your Cloudflare email
        .header("X-Auth-Key", secrets.auth_key) // Using the Global API Key
        .json(&body)
        .send()
        .await?;

    if response.status().is_success() {
        println!("Successfully updated IP to: {}", new_ip);
    } else {
        eprintln!("Failed to update IP: {}", response.status());
    }

    Ok(())
}

async fn fetch_public_ip() -> Option<Ipv4Addr> {
    let trace_text = match reqwest::get("https://www.cloudflare.com/cdn-cgi/trace").await {
        Ok(response) => response.text().await.unwrap_or_default(),
        Err(_) => return None,
    };

    let ip_str = trace_text
        .lines()
        .find(|line| line.starts_with("ip="))
        .and_then(|line| line.split('=').nth(1));

    ip_str.and_then(|ip| ip.parse::<Ipv4Addr>().ok())
}
