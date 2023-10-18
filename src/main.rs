use crate::DynDnsError::GettingDomainIdError;
use anyhow::Result;
use dns_lookup::lookup_host;
use lazy_static::lazy_static;
use reqwest;
use reqwest::header::CONTENT_TYPE;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::str::Split;
use thiserror::Error;
use toml;

const IFCONFIG_URL: &str = "https://ifconfig.io/ip";

/*

https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-update-dns-record

https://api.cloudflare.com/client/v4
/zones/{zone_identifier}/dns_records/{identifier}

curl --request PUT \
  --url https://api.cloudflare.com/client/v4/zones/zone_identifier/dns_records/identifier \
  --header 'Content-Type: application/json' \
  --header 'X-Auth-Email: ' \
  --data '{
  "content": "198.51.100.4",
  "name": "example.com",
  "proxied": false,
  "type": "A",
  "comment": "Domain verification record",
  "tags": [
    "owner:dns-team"
  ],
  "ttl": 3600
}'
*/

#[derive(Error, Debug)]
pub enum DynDnsError {
    #[error("Getting Domain Id Error: `{0}`")]
    GettingDomainIdError(String),
    #[error("Unknown Dyndns process error: `{0}`")]
    Unknown(String),
}

#[derive(Debug, Serialize)]
struct Ttl(u8);

impl Ttl {
    fn new(ttl: u8) -> Ttl {
        if ttl < 60 {
            Ttl(60)
        } else {
            Ttl(ttl)
        }
    }
}

#[derive(Serialize)]
struct Data {
    content: String,
    name: String,
    proxied: Option<bool>,
    #[serde(rename(serialize = "type"))]
    ttype: String,
    comment: Option<String>,
    tags: Option<Vec<String>>,
    ttl: Option<Ttl>,
}

#[derive(Debug)]
enum ProcessResult {
    Success,
    Failed(String),
}

#[derive(Debug, Deserialize)]
struct Config {
    domain_name: String,
    api_token: String,
    zone_identifier: String,
    ttl: Option<u8>,
    comment: Option<String>,
}

lazy_static! {
    static ref CONFIG: Config = read_config().unwrap();
}

fn main() {
    match need_to_request_to_cloudflare(CONFIG.domain_name.as_str()) {
        Ok(true) => match update_dns() {
            Ok(x) => {
                println!("Success!: {:?}", x);
            }
            Err(x) => {
                println!("Failed!: {:?}", x);
            }
        },
        Ok(false) => {
            println!("Domain name and ip matched. Don't need to run.");
        }
        Err(x) => {
            panic!("Error: {:?}", x);
        }
    }
}

fn read_config() -> Result<Config> {
    let mut file: File;
    if let Ok(file0) = File::open("cloudflare-dyndns-config.toml") {
        file = file0;
    } else {
        if let Ok(file0) = File::open("/etc/cloudflare-dyndns-config.toml") {
            file = file0;
        } else {
            panic!("Error from reading config file. Please check 'cloudflare-dyndns-config.toml' at program's running path or /etc folder");
        }
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");
    let config: Config = toml::from_str(contents.as_str()).unwrap();
    //println!("{:?}", config);
    Ok(config)
}

fn get_my_ip() -> Result<IpAddr> {
    let mut res = reqwest::blocking::get(IFCONFIG_URL)?;
    let mut body = String::new();
    res.read_to_string(&mut body)?;
    if body.ends_with("\n") {
        body.pop();
    }
    let mut ip: Split<&str> = body.split(".");
    Ok(IpAddr::V4(Ipv4Addr::new(
        ip.next().unwrap().parse()?,
        ip.next().unwrap().parse()?,
        ip.next().unwrap().parse()?,
        ip.next().unwrap().parse()?,
    )))
}

fn api_endpoint() -> Result<String> {
    let zone_identifier = CONFIG.zone_identifier.as_str();
    Ok(format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_identifier}/dns_records"
    ))
}

fn api_key() -> Result<&'static str> {
    Ok(CONFIG.api_token.as_str())
}

fn get_dns_name() -> Result<(String, String)> {
    let domain_name = CONFIG.domain_name.to_owned();
    let mut a: Vec<&str> = domain_name.split(".").collect();

    let domain = format!(
        "{}.{}",
        a.get(a.len() - 2).unwrap(),
        a.get(a.len() - 1).unwrap()
    );
    let mut subdomain = String::new();
    for n in 0..a.len() - 2 {
        subdomain.push_str(a.get(n).unwrap());
    }
    Ok((subdomain, domain))
}

//fn update_dns(dns_name: &str, ip: IpAddr, data: Data) -> Result() {
fn update_dns() -> anyhow::Result<ProcessResult> {
    let api_key = api_key().expect("Trouble getting api key");
    let mut this_api_endpoint = String::new();

    if let Some(dns_id) = get_dns_id(CONFIG.domain_name.as_str())? {
        this_api_endpoint = format!(
            "{}/{}",
            api_endpoint().expect("Trouble getting api endpoint"),
            dns_id
        );
    } else {
        return Ok(ProcessResult::Failed("DNS name not found".to_string()));
    }

    let data = Data {
        content: get_my_ip()?.to_string(),
        name: get_dns_name()?.0,
        proxied: Some(false),
        ttype: "A".to_string(),
        comment: CONFIG.comment.clone(),
        tags: None,
        ttl: Some(Ttl::new(60)),
    };

    let payload = serde_json::to_string(&data).unwrap();
    let client = reqwest::blocking::Client::new();
    let res = client
        .put(this_api_endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header("Authorization", format!("Bearer {api_key}"))
        .body(payload)
        .send()?;

    //println!("{:?}", res);
    if res.status() == StatusCode::OK {
        return Ok(ProcessResult::Success);
    } else {
        return Ok(ProcessResult::Failed(
            "Cloudflair API call faield".to_string(),
        ));
    }
}

fn get_dns_id(name: &str) -> Result<Option<String>> {
    let api_key = api_key().expect("Trouble getting api key");
    let api_endpoint = api_endpoint().expect("Trouble getting api endpoint");
    let client = reqwest::blocking::Client::new();
    let res = client
        .get(api_endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header("Authorization", format!("Bearer {api_key}"))
        .send()?;
    if res.status() != StatusCode::OK {
        return Err(GettingDomainIdError(res.status().to_string()).into());
    }
    let body = res
        .text()
        .expect("Trouble getting body from get_dns_id response");
    let v: Value = serde_json::from_str(&body.as_str())?;
    for i in v.get("result").unwrap().as_array().unwrap().iter() {
        if i.get("name").unwrap() == name {
            return Ok(Some(i.get("id").unwrap().as_str().unwrap().to_string()));
        }
    }
    Ok(None)
}

fn query_dns(hostname: &str) -> Vec<IpAddr> {
    lookup_host(hostname).unwrap()
}

fn need_to_request_to_cloudflare(hostname: &str) -> Result<bool> {
    let my_ip = get_my_ip()?;
    if query_dns(hostname).contains(&my_ip) {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_my_ip() {
        println!("{:?}", get_my_ip());
    }
    #[test]
    fn test_update_dns() {
        println!("{:?}", update_dns());
    }
    #[test]
    fn test_get_dns_id() {
        println!("{:?}", get_dns_id("dns_test.seungjin.net"));
    }
    #[test]
    fn test_query_dns() {
        println!("{:?}", query_dns("seungjin.net"));
    }
    #[test]
    fn test_need_to_request_to_cloudflare() {
        println!("{:?}", need_to_request_to_cloudflare("seungjin.net"));
    }
    #[test]
    fn test_read_config() {
        println!("{:?}", read_config());
    }
    #[test]
    fn test_get_dns_name() {
        println!("{:?}", get_dns_name());
    }
}
