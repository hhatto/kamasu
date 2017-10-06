use std::path::Path;
use std::io::prelude::*;
use std::fs::File;
use regex::Regex;
use hyper;
use futures;
use futures::Future;
use hyper::{header, Client, StatusCode, Body, Headers};
use hyper::client::HttpConnector;
use hyper::server::{self, Service, Request, Response};

pub struct Proxy {
    pub routes: Vec<String>,
    pub client: Client<HttpConnector, Body>,
    pub docroot: String,
    pub static_content_target: Option<Regex>,
}

impl Service for Proxy {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response, Error=Self::Error>>;

    fn call(&self, req: server::Request) -> Self::Future {
        let uri = req.uri().clone();
        let fut = {
            if let Some(ref re) = self.static_content_target {
                if re.is_match(uri.path()) {
                    println!("match static content: {}", uri.path());
                    let path = Path::new(self.docroot.as_str()).join(uri.path().trim_matches('/'));
                    let mut body: Vec<u8> = vec![];
                    match File::open(&path) {
                        Ok(mut file) => {
                            match file.read_to_end(&mut body) {
                                Err(e) => {
                                    println!("read file error: {}", e);
                                    return Box::new({
                                        futures::future::ok(
                                            Response::new()
                                            .with_status(StatusCode::ServiceUnavailable))
                                    });
                                },
                                Ok(_) => {},
                            }
                        }
                        Err(e) => {
                            println!("open file error. file={:?} err={}", path, e);
                            return Box::new({
                                futures::future::ok(
                                    Response::new().with_status(StatusCode::NotFound))
                            });
                        },
                    }
                    let mut headers = Headers::new();
                    headers.set(header::ContentType::octet_stream());
                    headers.set(header::ContentLength(body.len() as u64));
                    return Box::new({
                        futures::future::ok(
                            Response::new()
                            .with_status(StatusCode::Ok)
                            .with_headers(headers)
                            .with_body(body))
                    }) as Self::Future;
                }
            }

            // load blancing, port-hash now
            let index = if let Some(addr) = req.remote_addr() {
                addr.port() % (self.routes.len() as u16)
            } else {
                0
            } as usize;
            let backend_addr = self.routes[index].clone();

            // create request
            let url_str = match uri.query() {
                Some(query) => format!("http://{}{}?{}", backend_addr, uri.path(), query),
                None => format!("http://{}{}", backend_addr, uri.path()),
            };
            let url = url_str.parse::<hyper::Uri>().expect("uri error");
            let mut proxied_req = hyper::client::Request::new(req.method().clone(), url);
            *proxied_req.headers_mut() = req.headers().clone();
            proxied_req.set_body(req.body());

            // request to backend server
            let req = self.client.request(proxied_req);
            Box::new(req.then(|res| {
                if let Ok(res) = res {
                    futures::future::ok(
                        Response::new()
                        .with_status(res.status().clone())
                        .with_headers(res.headers().clone())
                        .with_body(res.body()))
                } else {
                    futures::future::ok(
                        Response::new()
                        .with_status(StatusCode::ServiceUnavailable))
                }
            })) as Self::Future
        };
        fut
    }
}
