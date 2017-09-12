extern crate hyper;
extern crate futures;
extern crate tokio_tls;
extern crate native_tls;
extern crate tokio_core;
extern crate httpbis;
extern crate tls_api_openssl;

use std::thread;
use std::str::FromStr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_core::reactor::Core;
use futures::{future, Stream, Future};
use tls_api_openssl::TlsAcceptor;

struct Proxy4Http2 {
    routes: Arc<Vec<String>>,
    roundrobin_counter: Arc<AtomicUsize>,
}

impl Proxy4Http2 {
    fn new(routes: Vec<String>) -> Self {
        Self {
            routes: Arc::new(routes),
            roundrobin_counter: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl httpbis::Service for Proxy4Http2 {
    fn start_request(&self, headers: httpbis::Headers, _req: httpbis::HttpPartStream)
        -> httpbis::Response
    {
        let mut core = Core::new().expect("http2 backend client core error");
        let handle = core.handle();
        let backend_client = hyper::Client::new(&handle);

        // FIXME: only use index 0
        let backend_index = self.roundrobin_counter.fetch_add(1, Ordering::Relaxed);
        let backend_addr = self.routes[backend_index % self.routes.len()].clone();

        let url_str = format!("http://{}{}", backend_addr, headers.path());
        let url = url_str.parse::<hyper::Uri>().expect("uri error");
        let proxied_req = hyper::client::Request::new(
            hyper::Method::from_str(headers.method()).expect("invalid method"), url);
        let mut backend_req_headers = hyper::header::Headers::new();
        for req_header in headers.0 {
            if req_header.name()[0] as char == ':' {
                continue;
            }
            backend_req_headers.set_raw(
                String::from_utf8(req_header.name().into()).unwrap(),
                req_header.value());
        }

        // TODO: set request body
        //proxied_req.set_body(req.body());

        // NOTE: sync request/response
        let req = backend_client.request(proxied_req);
        let work = req.and_then(|res| {
            Ok(res)
        });
        let backend_resp = core.run(work).expect("backend client error");

        // set origin status code and headers
        let mut resp_headers = httpbis::Headers::from_status(
            backend_resp.status().as_u16() as u32);
        for header in backend_resp.headers().iter() {
            match header.name().to_lowercase().as_str() {
                "host" | "connection" => continue,
                _ => {}
            }
            resp_headers.add(header.name().to_lowercase().as_str(), header.value_string().as_str());
        }

        // read body and set http2 response body
        let body: Vec<u8> = vec![];
        let w = backend_resp.body().fold(body, |mut acc, chunk| {
            acc.extend_from_slice(chunk.as_ref());
            Ok::<_, hyper::Error>(acc)
        }).and_then(move |body_vec| {
            future::ok(body_vec)
        });
        let body = core.run(w).expect("backend client error");
        let b = String::from_utf8(body).unwrap();

        httpbis::Response::headers_and_bytes(resp_headers, b)
    }
}

pub fn spawn_proxy(routes: Vec<String>, addr_str: String, acceptor: TlsAcceptor) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let addr: SocketAddr = addr_str.as_str().parse().unwrap();
        let port = addr.port();
        let host = addr.ip();

        let mut conf = httpbis::ServerConf::new();
        conf.alpn = Some(httpbis::ServerAlpn::Require);
        let mut server = httpbis::ServerBuilder::new();
        server.set_port(port);
        server.set_tls(acceptor);
        server.conf = conf;
        server.service.set_service("/", Arc::new(Proxy4Http2::new(routes)));
        let server = server.build().expect("http2 server build error");

        println!("Listening on {}:{} with http2", host, server.local_addr().port());
        loop {
            thread::park();
        }
    })
}
