use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::{Arg, Command as ClapCommand};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BASE_PORT: i32 = 60000;

struct PHPSpawnOption {
    host: String,
    docroot: String,
    phpini: String,
}

fn spawn_php_server_process(opts: &PHPSpawnOption, n: usize, procs: &mut Vec<(Child, String)>) {
    for port_offset in 0..n {
        let port = BASE_PORT + port_offset as i32;
        let backend_addr = format!("{}:{}", opts.host, port);
        let ret = Command::new("php")
            .arg("-S")
            .arg(backend_addr.clone())
            .arg("-t")
            .arg(opts.docroot.as_str())
            .arg("-c")
            .arg(opts.phpini.as_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("php command not execution");
        procs.push((ret, backend_addr));
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[derive(Clone)]
struct ProxyState {
    routes: Arc<Vec<String>>,
    counter: Arc<AtomicUsize>,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Incoming>,
}

async fn handle_request(
    req: Request<Incoming>,
    state: ProxyState,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Round-robin load balancing
    let index = state.counter.fetch_add(1, Ordering::Relaxed) % state.routes.len();
    let backend_addr = &state.routes[index];

    // Build backend URL
    let uri = req.uri();
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let backend_url = format!("http://{}{}", backend_addr, path_and_query);

    // Create proxied request
    let (parts, body) = req.into_parts();
    let mut proxied_req = Request::builder().method(parts.method).uri(&backend_url);

    // Copy headers
    for (key, value) in parts.headers.iter() {
        if key != hyper::header::HOST {
            proxied_req = proxied_req.header(key, value);
        }
    }

    let proxied_req = match proxied_req.body(body) {
        Ok(req) => req,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(empty())
                .unwrap());
        }
    };

    // Forward to backend
    match state.client.request(proxied_req).await {
        Ok(res) => {
            let (parts, body) = res.into_parts();
            let body = body.map_err(|e| e).boxed();
            Ok(Response::from_parts(parts, body))
        }
        Err(_) => Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(full("Backend unavailable"))
            .unwrap()),
    }
}

async fn run_http_server(
    addr: SocketAddr,
    state: ProxyState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                handle_request(req, state)
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("HTTP error: {}", e);
            }
        });
    }
}

fn generate_self_signed_cert(
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(signing_key.serialize_der())
        .map_err(|e| format!("key error: {}", e))?;

    Ok((vec![cert_der], key_der))
}

fn load_certs_from_file(
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let certs = CertificateDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key_from_file(path: &str) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let key = PrivateKeyDer::from_pem_file(path)?;
    Ok(key)
}

async fn run_https_server(
    addr: SocketAddr,
    state: ProxyState,
    tls_acceptor: TlsAcceptor,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on https://{} (HTTP/2 enabled)", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let state = state.clone();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("TLS accept error: {}", e);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);

            let service = service_fn(move |req| {
                let state = state.clone();
                handle_request(req, state)
            });

            // Use HTTP/2
            if let Err(e) = http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                eprintln!("HTTP/2 error: {}", e);
            }
        });
    }
}

#[tokio::main]
async fn main() {
    // Install ring as the default crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let app = ClapCommand::new(APP_NAME)
        .version(VERSION)
        .about("Reverse Proxy for PHP built-in Server")
        .arg(
            Arg::new("server")
                .short('S')
                .value_name("ADDR")
                .help("Run with HTTP Web Server"),
        )
        .arg(
            Arg::new("https")
                .long("https")
                .value_name("ADDR")
                .help("Run with HTTPS/HTTP2 Web Server"),
        )
        .arg(
            Arg::new("cert")
                .long("cert")
                .value_name("FILE")
                .help("TLS certificate file (PEM format)"),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .value_name("FILE")
                .help("TLS private key file (PEM format)"),
        )
        .arg(
            Arg::new("procs")
                .short('n')
                .value_name("PROCS")
                .help("Spawn N php procs"),
        )
        .arg(
            Arg::new("phpini")
                .short('c')
                .value_name("FILE_OR_DIR")
                .help("Specify php.ini file or in this directory"),
        )
        .arg(
            Arg::new("docroot")
                .short('t')
                .value_name("DIR")
                .help("Specify document root <docroot>"),
        );

    let matches = app.get_matches();

    // bind address
    let http_addr = matches.get_one::<String>("server").map(|v| v.to_string());

    let https_addr = matches.get_one::<String>("https").map(|v| v.to_string());

    // PHP docroot
    let docroot = matches
        .get_one::<String>("docroot")
        .map(|v| v.as_str())
        .unwrap_or("./");

    // php.ini path or directory
    let phpini = matches
        .get_one::<String>("phpini")
        .map(|v| v.as_str())
        .unwrap_or("./");

    // N procs
    let proc_num: usize = matches
        .get_one::<String>("procs")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10);

    // Spawn PHP server processes
    let mut procs = vec![];
    let phpopts = PHPSpawnOption {
        host: "127.0.0.1".to_string(),
        phpini: phpini.to_string(),
        docroot: docroot.to_string(),
    };
    spawn_php_server_process(&phpopts, proc_num, &mut procs);

    let routes: Vec<String> = procs.iter().map(|p| p.1.clone()).collect();

    // Wait for PHP processes to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create shared state
    let client = Client::builder(TokioExecutor::new()).build_http();
    let state = ProxyState {
        routes: Arc::new(routes),
        counter: Arc::new(AtomicUsize::new(0)),
        client,
    };

    let mut handles = vec![];

    // Start HTTP server
    if let Some(addr_str) = http_addr {
        let addr: SocketAddr = addr_str.parse().expect("Invalid HTTP address");
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_http_server(addr, state).await {
                eprintln!("HTTP server error: {}", e);
            }
        }));
    }

    // Start HTTPS/HTTP2 server
    if let Some(addr_str) = https_addr {
        let addr: SocketAddr = addr_str.parse().expect("Invalid HTTPS address");

        // Load or generate certificates
        let (certs, key) = match (
            matches.get_one::<String>("cert"),
            matches.get_one::<String>("key"),
        ) {
            (Some(cert_path), Some(key_path)) => {
                let certs = load_certs_from_file(cert_path).expect("Failed to load certificate");
                let key = load_key_from_file(key_path).expect("Failed to load private key");
                (certs, key)
            }
            _ => {
                println!("No certificate specified, generating self-signed certificate...");
                generate_self_signed_cert().expect("Failed to generate self-signed certificate")
            }
        };

        // Configure TLS with ALPN for HTTP/2
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("Failed to configure TLS");

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let tls_acceptor = TlsAcceptor::from(Arc::new(config));
        let state = state.clone();

        handles.push(tokio::spawn(async move {
            if let Err(e) = run_https_server(addr, state, tls_acceptor).await {
                eprintln!("HTTPS server error: {}", e);
            }
        }));
    }

    // If no server specified, default to HTTP on 127.0.0.1:8000
    if handles.is_empty() {
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        if let Err(e) = run_http_server(addr, state).await {
            eprintln!("Server error: {}", e);
        }
    } else {
        // Wait for all servers
        for handle in handles {
            let _ = handle.await;
        }
    }

    // Cleanup PHP processes
    for mut p in procs {
        let _ = p.0.kill();
    }
}
