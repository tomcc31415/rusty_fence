use std::net::IpAddr;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

async fn resolve_domain(domain: &str) -> Result<Vec<IpAddr>, String> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        .map_err(|e| format!("Error creating resolver: {}", e))?;

    let response = resolver
        .lookup_ip(domain)
        .await
        .map_err(|e| format!("Error resolving domain: {}", e))?;

    Ok(response.iter().collect())
}

fn is_domain_blocked(domain: &str, blocklist: &[&str]) -> bool {
    blocklist.contains(&domain)
}

#[tokio::main]
async fn main() {
    let domain = "blocked.example.com";
    let blocklist = vec![
        "blocked.example.com",
        "another.example.com",
        "third.ex.a.m.p.example.com",
    ];

    if is_domain_blocked(domain, &blocklist) {
        println!("The domain {} is blocked.", domain);
    } else {
        match resolve_domain(domain).await {
            Ok(ips) => println!("The domain {} resolved to: {:?}", domain, ips),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}
