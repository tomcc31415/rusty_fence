use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use structopt::StructOpt;
use trust_dns_proto::rr::RData;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_server::proto::op::{Message, MessageType, OpCode};
use trust_dns_server::proto::rr::domain::Name;
use trust_dns_server::proto::rr::Record;

static ZERO_IP_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

#[derive(Debug, StructOpt)]
#[structopt(name = "dns-filter", about = "A simple DNS filtering server.")]
struct Opt {
    #[structopt(short, long, default_value = "5300")]
    port: u16,

    #[structopt(short, long, default_value = "hosts/hosts.txt")]
    blocklist_path: String,

    #[structopt(short, long)]
    verbose: bool,

    #[structopt(short = "t", long, default_value = "2")]
    worker_threads: usize,
}

fn main() {
    let opt = Opt::from_args();
    let config = ServerConfig::from_opt(&opt);

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.worker_threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_server(config));
}

async fn run_server(config: ServerConfig) {
    let blocklist = process_file(&config.blocklist_path);

    let socket = Arc::new(
        tokio::net::UdpSocket::bind(("0.0.0.0", config.port))
            .await
            .unwrap(),
    );
    println!("Listening on port {}", config.port);

    let mut buf = [0; 512];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
        let blocklist_ref = blocklist.clone();
        let socket_ref = socket.clone();
        let config_ref = config.clone();
        tokio::spawn(async move {
            handle_request(&config_ref, &blocklist_ref, &buf[..len], addr, &socket_ref).await;
        });
    }
}

struct ServerConfig {
    port: u16,
    blocklist_path: String,
    verbose: bool,
    worker_threads: usize,
}

impl ServerConfig {
    fn from_opt(opt: &Opt) -> Self {
        Self {
            port: opt.port,
            blocklist_path: opt.blocklist_path.clone(),
            verbose: opt.verbose,
            worker_threads: opt.worker_threads,
        }
    }
}

impl Clone for ServerConfig {
    fn clone(&self) -> Self {
        Self {
            port: self.port,
            blocklist_path: self.blocklist_path.clone(),
            verbose: self.verbose,
            worker_threads: self.worker_threads,
        }
    }
}

async fn resolve_domain(domain: &str) -> Result<Vec<IpAddr>, String> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        .map_err(|e| format!("Error creating resolver: {}", e))?;

    let response = resolver
        .lookup_ip(domain)
        .await
        .map_err(|e| format!("Error resolving domain: {}", e))?;
    Ok(response.iter().collect())
}

async fn lookup_ip_address(
    config: &ServerConfig,
    domain: &str,
    blocklist: &HashSet<String>,
) -> Vec<IpAddr> {
    if blocklist.contains(domain) {
        if config.verbose {
            println!("Domain {} is in the blocklist", domain);
        }
        vec![ZERO_IP_ADDRESS]
    } else {
        if config.verbose {
            println!("Resolving domain {}", domain);
        }
        let result = resolve_domain(domain).await.unwrap_or_else(|_| vec![]);
        if config.verbose {
            println!("Resolved {} to {:?}", domain, result);
        }
        result
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
            let domain = parts[1].trim().to_string();
            if !domain.ends_with('.') {
                let domain_with_dot = format!("{}.", domain);
                hash_set.insert(domain_with_dot.clone());
            } else {
                hash_set.insert(domain.clone());
            }
        }
    }

    hash_set
}

async fn handle_request(
    config: &ServerConfig,
    blocklist: &HashSet<String>,
    buf: &[u8],
    addr: SocketAddr,
    socket: &tokio::net::UdpSocket,
) {
    let request = match Message::from_vec(buf) {
        Ok(msg) => msg,
        Err(_) => return,
    };

    if request.message_type() == MessageType::Query && request.op_code() == OpCode::Query {
        if let Some(query) = request.queries().first() {
            let name = query.name().to_utf8();
            let ips = lookup_ip_address(config, &name, blocklist).await;

            if config.verbose {
                println!("Handling request for domain {}", name);
            }

            let mut response = Message::new();
            response.set_id(request.id());
            response.set_message_type(MessageType::Response);
            response.set_op_code(OpCode::Query);
            response.set_authoritative(true);
            response.set_recursion_desired(request.recursion_desired());
            response.set_recursion_available(true);

            for ip in ips {
                if let IpAddr::V4(ipv4) = ip {
                    let record = Record::from_rdata(
                        Name::from_utf8(query.name().to_utf8().as_str()).unwrap(),
                        60,
                        RData::A(ipv4),
                    );
                    response.add_answer(record);
                }
            }

            let response_bytes = response.to_vec().unwrap();
            socket.send_to(&response_bytes, addr).await.unwrap();
        }
    }
}
