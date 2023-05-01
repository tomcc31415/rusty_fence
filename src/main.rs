use dashmap::DashMap;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use structopt::StructOpt;
use trust_dns_proto::rr::RData;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_server::proto::op::{Message, MessageType, OpCode};
use trust_dns_server::proto::rr::domain::Name;
use trust_dns_server::proto::rr::Record;

static DNS_CACHE: Lazy<Mutex<DashMap<String, (HashSet<IpAddr>, u64)>>> =
    Lazy::new(|| Mutex::new(DashMap::new()));

//static ZERO_IP_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
static ZERO_IP_SET: Lazy<HashSet<IpAddr>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    set
});

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
    let blocklist = Arc::new(process_file(&config.blocklist_path));

    let socket = Arc::new(
        tokio::net::UdpSocket::bind(("0.0.0.0", config.port))
            .await
            .unwrap(),
    );
    println!("Listening on port {}", config.port);

    let (tx, _) = tokio::sync::broadcast::channel::<(Vec<u8>, SocketAddr)>(100);
    let resolver = Arc::new(
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            .expect("Error creating resolver"),
    );

    for _ in 0..config.worker_threads {
        let tx = tx.clone();
        let mut rx = tx.subscribe(); // Create a new receiver for each worker
        let blocklist = blocklist.clone();
        let socket = socket.clone();
        let config = config.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            while let Ok((buf, addr)) = rx.recv().await {
                handle_request(&config, &blocklist, &buf, addr, &socket, &resolver).await;
            }
        });
    }

    let mut buf = [0; 4096];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
        let buf = buf[..len].to_vec();
        if let Err(_) = tx.send((buf, addr)) {
            eprintln!("Error sending data to worker");
        }
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

fn get_from_cache_or_resolve(config: &ServerConfig, domain: &str) -> Option<HashSet<IpAddr>> {
    let cache = DNS_CACHE.lock();

    // Check cache first
    if let Some(ref_entry) = cache.get(domain) {
        if config.verbose {
            println!("Using cached IPs for domain {}", domain);
        }
        return Some(ref_entry.value().0.clone());
    }
    None
}

async fn lookup_ip_address(
    config: &ServerConfig,
    domain: &str,
    blocklist: &HashSet<Name>,
    resolver: &TokioAsyncResolver,
) -> HashSet<IpAddr> {
    // Check blocklist first
    if blocklist.contains(&Name::from_str(domain).unwrap()) {
        if config.verbose {
            println!("Domain {} is in the blocklist", domain);
        }
       // let mut zero_ips = HashSet::new();
       // zero_ips.insert(ZERO_IP_ADDRESS);
       // return zero_ips;
        return ZERO_IP_SET.clone()
    }

    // Check the cache
    if let Some(cached_entry) = get_from_cache_or_resolve(config, domain) {
        return cached_entry;
    }

    // If not in cache, make a DNS query
    if config.verbose {
        println!("Resolving domain {}", domain);
    }
    let response = match resolver.lookup_ip(domain).await {
        Ok(lookup_ip) => lookup_ip,
        Err(_) => {
            if config.verbose {
                eprintln!("Error resolving domain {}", domain);
            }
            return HashSet::new();
        }
    };

    let result: HashSet<IpAddr> = response.iter().collect();
    if config.verbose {
        println!("Resolved {} to {:?}", domain, result);
    }

    // Update cache
    let cache = DNS_CACHE.lock();

    if cache.len() >= 2000000 {
        cache.clear();
        println!("Cache is full. Clearing all entries.");
    }

    cache.insert(
        domain.to_string(),
        (
            result.clone(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ),
    );

    result
}

fn process_file(file_path: &str) -> HashSet<Name> {
    let file = File::open(file_path).unwrap();
    let reader = BufReader::new(file);
    let mut hash_set = HashSet::new();

    for line in reader.lines() {
        let line = line.unwrap();
        let domain = line.trim().to_string();
        if !domain.ends_with('.') {
            let domain_with_dot = format!("{}.", domain);
            match Name::from_ascii(domain_with_dot.clone()) {
                Ok(name) => {
                    hash_set.insert(name);
                }
                Err(e) => {
                    eprintln!("Error parsing domain {}: {}", domain_with_dot, e);
                }
            }
        } else {
            match Name::from_ascii(domain.clone()) {
                Ok(name) => {
                    hash_set.insert(name);
                }
                Err(e) => {
                    eprintln!("Error parsing domain {}: {}", domain, e);
                }
            }
        }
    }

    hash_set
}

async fn handle_request(
    config: &ServerConfig,
    blocklist: &Arc<HashSet<Name>>,
    buf: &[u8],
    addr: SocketAddr,
    socket: &tokio::net::UdpSocket,
    resolver: &Arc<TokioAsyncResolver>,
) {
    let request = match Message::from_vec(buf) {
        Ok(msg) => msg,
        Err(_) => return,
    };

    if request.message_type() == MessageType::Query && request.op_code() == OpCode::Query {
        if let Some(query) = request.queries().first() {
            let name = query.name().to_utf8();
            let ips = lookup_ip_address(config, &name, blocklist, resolver).await;

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
