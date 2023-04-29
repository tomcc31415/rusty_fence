use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

static ZERO_IP_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

async fn resolve_domain(domain: &str) -> Result<Vec<IpAddr>, String> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        .map_err(|e| format!("Error creating resolver: {}", e))?;

    let response = resolver
        .lookup_ip(domain)
        .await
        .map_err(|e| format!("Error resolving domain: {}", e))?;

    Ok(response.iter().collect())
}

async fn lookup_ip_adress(domain: &str, hash_set: HashSet<String>) -> Result<Vec<IpAddr>, String> {
    if hash_set.contains(domain) {
        return Ok(vec![ZERO_IP_ADDRESS]);
    } else {
        return resolve_domain(domain).await;
    }
}

fn process_file(file_path: &str) -> HashSet<String> {
    let file = File::open(file_path).unwrap();
    let reader = BufReader::new(file);
    let mut hash_set = HashSet::new();

    for line in reader.lines() {
        let line = line.unwrap();
        let parts: Vec<&str> = line.split(' ').collect();

        if parts.len() == 2 {
            let domain = parts[1].trim();
            hash_set.insert(domain.to_string());
        }
    }

    hash_set
}

#[tokio::main]
async fn main() {
    let domain_test = "zzmalwo.pl";
    let file_path = "hosts/hosts.txt";
    let blocklist_hashset = process_file(file_path);

    let answer = lookup_ip_adress(domain_test, blocklist_hashset).await;
    println!("Lookup for {}: {:?}", domain_test, answer);
}
