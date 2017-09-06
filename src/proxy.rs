use hyper;
use futures;
use futures::Future;
use hyper::{Client, StatusCode, Body};
use hyper::client::HttpConnector;
use hyper::server::{self, Service, Request, Response};

pub struct Proxy {
    pub routes: Vec<String>,
    pub client: Client<HttpConnector, Body>,
}

impl Service for Proxy {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response, Error=Self::Error>>;

    fn call(&self, req: server::Request) -> Self::Future {
        let uri = req.uri().clone();
        let fut = {
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
