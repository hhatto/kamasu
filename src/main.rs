extern crate hyper;
extern crate futures;
extern crate tokio_core;
extern crate clap;

use std::process::Child;
use std::thread::sleep;
use std::time::Duration;
use std::process::{Command, Stdio};
use futures::{Stream, Future};
use hyper::server::Http;

use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;
use clap::{App, Arg};

mod proxy;

const BASE_PORT: i32 = 60000;
const APP_NAME: &'static str = "kamasu";
const VERSION: &'static str = "0.1.1";

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

fn main() {
    let app = App::new(APP_NAME)
        .version(VERSION)
        .arg(Arg::with_name("server")
             .short("S")
             .takes_value(true)
             .value_name("ADDR")
             .help("Run with web server"))
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
        Some(v) => v,
        None => "127.0.0.1:8000",
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

    let mut procs = vec![];
    let mut core = Core::new().unwrap();
    let http = Http::new();
    let handle = core.handle();
    let backend_client = hyper::Client::new(&handle);

    let addr = addr_str.parse().unwrap();
    let sock = TcpListener::bind(&addr, &handle)
        .expect(format!("bind error. addr={}", addr).as_str());
    let host = format!("{}", sock.local_addr().unwrap().ip());
    let port = sock.local_addr().unwrap().port();

    println!("Listening on {}:{}", host, port);

    let phpopts = PHPSpawnOption {
        host: host,
        phpini: phpini.to_string(),
        docroot: docroot.to_string(),
    };

    spawn_php_server_process(&phpopts, proc_num, &mut procs);

    let routes: Vec<String> = procs.iter().map(|p| p.1.clone()).collect();
    let server = sock.incoming().for_each(|(client, client_addr)| {
        let service = proxy::Proxy {
            routes: routes.clone(),
            client: backend_client.clone()
        };
        futures::future::ok(client_addr).and_then(|client_addr| {
            http.bind_connection(&handle, client, client_addr, service);
            Ok(())
        })
    });

    core.run(server).unwrap();

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
