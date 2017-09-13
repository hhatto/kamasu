extern crate hyper;
extern crate futures;
extern crate tokio_core;
extern crate tokio_tls;
extern crate native_tls;
extern crate clap;
extern crate tls_api_openssl;
extern crate tls_api;

use std::thread::sleep;
use std::time::Duration;
use std::process::{Child, Command, Stdio};
use futures::{Stream, Future};
use hyper::server::Http;

use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;
use tokio_tls::TlsAcceptorExt;
use native_tls::{Pkcs12, TlsAcceptor};
use tls_api_openssl::TlsAcceptorBuilder;
use tls_api::TlsAcceptorBuilder as tls_api_TlsAcceptorBuilder;

use clap::{App, Arg};

mod proxy;
mod http2;

const BASE_PORT: i32 = 60000;
const APP_NAME: &'static str = "kamasu";
const VERSION: &'static str = "0.2.0";

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
            .arg("-S").arg(backend_addr.clone())
            .arg("-t").arg(opts.docroot.as_str())
            .arg("-c").arg(opts.phpini.as_str())
            .stdout(Stdio::null())
            .spawn()
            .expect("php command not execution");
        procs.push((ret, backend_addr));
    }
}

fn spawn_proxy(routes: Vec<String>, addr_str: String, https_acceptor: Option<TlsAcceptor>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let http = Http::new();
        let backend_client = hyper::Client::new(&handle);

        let addr = addr_str.as_str().parse().unwrap();
        let sock = TcpListener::bind(&addr, &handle)
            .expect(format!("bind error. addr={}", addr).as_str());
        let host = format!("{}", sock.local_addr().unwrap().ip());
        let port = sock.local_addr().unwrap().port();

        if let Some(https_acceptor) = https_acceptor {
            println!("Listening on {}:{} with https", host, port);
            let server = sock.incoming().for_each(|(client, client_addr)| {
                let service = proxy::Proxy {
                    routes: routes.clone(),
                    client: backend_client.clone(),
                };
                https_acceptor.accept_async(client).join(Ok(client_addr)).and_then(|(stream, client_addr)| {
                    http.bind_connection(&handle, stream, client_addr, service);
                    Ok(())
                }).or_else(|e| { println!("error accepting TLS connection: {}", e); Ok(()) })
            });
            core.run(server).unwrap();
        } else {
            println!("Listening on {}:{}", host, port);
            let server = sock.incoming().for_each(|(client, client_addr)| {
                let service = proxy::Proxy {
                    routes: routes.clone(),
                    client: backend_client.clone(),
                };
                futures::future::ok(client_addr).and_then(|client_addr| {
                    http.bind_connection(&handle, client, client_addr, service);
                    Ok(())
                })
            });
            core.run(server).unwrap();
        };
    })
}

fn main() {
    let app = App::new(APP_NAME)
        .version(VERSION)
        .about("Reverse Proxy for PHP built-in Server")
        .arg(Arg::with_name("server")
             .short("S")
             .takes_value(true)
             .value_name("ADDR")
             .help("Run with HTTP Web Server"))
        .arg(Arg::with_name("https")
             .short("s")
             .long("https")
             .takes_value(true)
             .value_name("ADDR")
             .help("Run with HTTPS Web Server"))
        .arg(Arg::with_name("http2")
             .short("h2")
             .long("http2")
             .takes_value(true)
             .value_name("ADDR")
             .help("Run with HTTP2 Web Server"))
        .arg(Arg::with_name("procs")
             .short("n")
             .takes_value(true)
             .value_name("PROCS")
             .help("Spawn N php procs"))
        .arg(Arg::with_name("phpini")
             .short("c")
             .takes_value(true)
             .value_name("FILE_OR_DIR")
             .help("Specify php.ini file or in this directory"))
        .arg(Arg::with_name("docroot")
             .short("t")
             .takes_value(true)
             .value_name("DIR")
             .help("Specify document root <docroot>"));

    let matches = app.get_matches();

    // bind address
    let addr_str = match matches.value_of("server") {
        Some(v) => v.to_string(),
        None => "127.0.0.1:8000".to_string(),
    };

    // PHP docroot
    let docroot = match matches.value_of("docroot") {
        Some(v) => v,
        None => "./",
    };

    // php.ini path or directory
    let phpini = match matches.value_of("phpini") {
        Some(v) => v,
        None => "./",
    };

    // N procs
    let proc_num: usize = match matches.value_of("procs") {
        Some(v) => {
            match v.parse::<usize>() {
                Ok(i) => i,
                Err(_) => 1,
            }
        },
        None => 10,
    };

    // spawn php server processes
    let mut procs = vec![];
    let phpopts = PHPSpawnOption {
        host: "127.0.0.1".to_string(),
        phpini: phpini.to_string(),
        docroot: docroot.to_string(),
    };
    spawn_php_server_process(&phpopts, proc_num, &mut procs);

    let routes: Vec<String> = procs.iter().map(|p| p.1.clone()).collect();

    let mut proxy_procs = vec![];
    proxy_procs.push(spawn_proxy(routes.clone(), addr_str, None));

    // use HTTPS
    match matches.value_of("https") {
        Some(addr) => {
            let der = include_bytes!("kamasu.p12");
            let cert = Pkcs12::from_der(der, APP_NAME).unwrap();
            proxy_procs.push(
                spawn_proxy(routes.clone(), addr.to_string(),
                Some(TlsAcceptor::builder(cert).unwrap().build().unwrap())));
        },
        None => {},
    };

    // use HTTP2
    match matches.value_of("http2") {
        Some(addr) => {
            let der = include_bytes!("kamasu.p12");
            let mut tls_acceptor = TlsAcceptorBuilder::from_pkcs12(der, APP_NAME).expect("acceptor build error");
            tls_acceptor.set_alpn_protocols(&[b"h2"]).expect("set_alpn_protocols error");

            proxy_procs.push(http2::spawn_proxy(
                    routes, addr.to_string(),
                    tls_acceptor.build().expect("tls acceptor build error")));
        },
        None => {},
    };

    loop {
        for p in procs.iter_mut() {
            match p.0.try_wait() {
                Ok(Some(status)) => {
                    println!("pid={}, exited with: {}", p.0.id(), status);
                },
                Ok(None) => {},
                Err(e) => println!("error occured: {}", e),
            }
        }
        sleep(Duration::from_millis(1_000));
    }
}
