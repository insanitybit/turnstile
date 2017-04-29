extern crate base64;
extern crate dogstatsd;
extern crate futures;
extern crate hyper;
extern crate serde_json;
extern crate serde;
extern crate time;
extern crate tokio_core;
extern crate ring;
extern crate uuid;

use super::*;
use std::cell::RefCell;
use std::fmt::Formatter;
use std::borrow::Cow;
use std::str::FromStr;

use errors::*;
use config::Config;
use metrics::DroppingMetrics as Dog;
use time::Duration;

use futures::future::FutureResult;

use base64::decode;

use ring::{digest, hmac};

use futures::Future;
use futures::Stream;

use hyper::{StatusCode, Client, Body, Headers, Method, Uri, HttpVersion};
use hyper::client::HttpConnector;
use hyper::server::{Service, Request, Response};
use hyper::header::{Authorization, ContentLength, ContentType, Date, HttpDate, Scheme};

use uuid::Uuid;
use slog;

static LOCAL_SERVER: &'static str = "localhost:9301";
static MAX_BODY_SIZE: usize = 10 * 1000000;

pub enum AuthorizationResult<'a> {
    MissingHeaders(Vec<&'static str>),
    InvalidHeader(Cow<'a, str>),
    UnsupportedAuthorizationScheme,
    UnsupportedDigest,
    UnAuthurized,
    SkewError,
    BodyReadFailure(hyper::Error)
}

pub struct Turnstile {
    client: Client<HttpConnector, Body>,
    secret: Vec<u8>,
    config: Config,
    logger: slog::Logger
}

//fn check_for_skew()

fn check_for_all_headers(headers: &Headers) -> Vec<&'static str> {
    let mut missing = Vec::new();

    if headers.get::<hyper::header::Host>().is_none() {
        missing.push("Host");
    };

    if headers.get::<hyper::header::Date>().is_none() {
        missing.push("Date");
    };

    if headers.get_raw("digest").is_none() {
        missing.push("Digest");
    };
    // TODO: Extra headers
    missing
}

fn bytes_to_algorithm(algorithm: &[u8]) -> std::result::Result<&'static ring::digest::Algorithm, AuthorizationResult<'static>> {
    if algorithm == b"SHA1" {
        Ok(&ring::digest::SHA1)
    } else if algorithm == b"SHA256" {
        Ok(&ring::digest::SHA256)
    } else if algorithm == b"SHA512" {
        Ok(&ring::digest::SHA512)
    } else {
        Err(AuthorizationResult::UnsupportedDigest)
    }
}

fn validate_body(algorithm: &[u8], digest: Vec<u8>, body: Body) -> std::result::Result<Vec<u8>, AuthorizationResult<'static>> {
    let algorithm = match bytes_to_algorithm(algorithm) {
        Ok(a) => a,
        Err(e) => return Err(e)
    };

    let mut ctx = digest::Context::new(algorithm);

    let res_body: Vec<_> = body.wait().collect();

    let mut body = Vec::new();

    for chunk in res_body {
        match chunk {
            Ok(bytes) => {
                body.extend_from_slice(bytes.as_ref());
                ctx.update(bytes.as_ref());
            },
            Err(e) => return Err(AuthorizationResult::BodyReadFailure(e))
        }
    }

    let body_digest = ctx.finish();
    match ring::constant_time::verify_slices_are_equal(&digest[..], body_digest.as_ref()) {
        Ok(_) => Ok(body),
        Err(_) => Err(AuthorizationResult::UnAuthurized)
    }
}

fn check_skew(skew: i64, date: &time::Tm) -> Result<()> {
    let dur = Duration::seconds(skew);

    let cur_time = time::now(); // TODO: Time should be collected as soon as the request comes in

    if cur_time - dur > *date || cur_time + dur < *date {
        bail!("Date is outside of skew range")
    }
    Ok(())
}

fn validate_headers(metric_dog: Dog, logger: slog::Logger, method: &Method, uri: &Uri, headers: &Headers, body: Body) -> std::result::Result<Vec<u8>, AuthorizationResult<'static>> {
    let mut metric_dog = metric_dog;
    {
        let missing = check_for_all_headers(headers);
        if !missing.is_empty() {
            return Err(AuthorizationResult::MissingHeaders(missing))
        }
    }
    // We know that the Date header must be present due to the previous check for all headers
    {
        let &Date(HttpDate(ref time)) = headers.get::<hyper::header::Date>().unwrap();
        if check_skew(10 * 60, time).is_err() {
            return Err(AuthorizationResult::SkewError)
        }
    }

    let (algorithm, digest) = match headers.get_raw("digest").map(get_digest).unwrap() {
        Ok((a, d)) => (a, d),
        Err(_) => return Err(AuthorizationResult::InvalidHeader("Digest".into()))
    };

    let body = validate_body(&algorithm[..], digest, body);


        let body = match body {
            Ok(body) => body,
            Err(e) => return Err(e)
        };

        if let Some(&Authorization(Rapid7HmacScheme { hash: ref token })) = headers.get::<Authorization<Rapid7HmacScheme>>() {
            let (key_id, signature) = match auth_parse(token) {
                Ok(pair) => pair,
                Err(_) => return Err(AuthorizationResult::InvalidHeader("Authorization".into()))
            };

            let mut data = Vec::new();

            let host_header = headers.get::<hyper::header::Host>().unwrap();
            let &Date(HttpDate(ref time)) = headers.get::<hyper::header::Date>().unwrap();
            let digest_header = headers.get_raw("digest").unwrap();


            let time = format!("{}", time.to_timespec().sec * 1000);

            let host = host_header.hostname();
            let port = host_header.port().map(|p| {
                let mut buf = String::from(":");
                buf.push_str(&p.to_string());
                buf
            }).unwrap_or("".to_owned());


            data.extend_from_slice(method.as_ref().as_bytes());
            data.extend_from_slice(b" ");
            data.extend_from_slice(uri.as_ref().as_bytes());
            data.extend_from_slice(b"\n");

            data.extend_from_slice(host.as_bytes());
            data.extend_from_slice(port.as_bytes());
            data.extend_from_slice(b"\n");


            data.extend_from_slice(time.as_bytes());
            data.extend_from_slice(b"\n");

            data.extend_from_slice(&key_id[..]);
            data.extend_from_slice(b"\n");

            data.extend_from_slice(digest_header.one().unwrap());
            data.extend_from_slice(b"\n");


            let key = hmac::VerificationKey::new(&digest::SHA256, &b"secret"[..]);


            if hmac::verify(&key, &data, &signature).is_ok() {
                metric_dog.incr("validated", &[]);
                Ok(body)
            } else {
                Err(AuthorizationResult::UnAuthurized)
            }
        } else {
            Err(AuthorizationResult::UnsupportedAuthorizationScheme)
        }
}

impl Turnstile {
    pub fn new(client: Client<HttpConnector, Body>, secret: Vec<u8>, config: Config, logger: slog::Logger) -> Turnstile {
        Turnstile {
            client: client,
            secret: secret,
            config: config,
            logger: logger.clone(),
        }
    }

    fn gen_request(&self, client_method: Method, client_uri: Uri, client_version: HttpVersion, client_headers: Headers, client_body: Vec<u8>) -> Result<hyper::client::Request> {
        let uri = format_dest_url(&client_uri, &self.config.service.scheme)?;

        let mut new_req = hyper::client::Request::new(client_method, uri);

        new_req.set_version(client_version);
        new_req.set_body(client_body);

        *new_req.headers_mut() = client_headers.clone();
        let correlation_id = get_or_gen_correlation_id(&client_headers);

        if let Cow::Owned(id) = correlation_id {
            new_req.headers_mut().set_raw("X-Request-Identifier", id)
        }

        Ok(new_req)
    }
}

#[derive(Debug, Clone)]
pub struct Rapid7HmacScheme {
    hash: String
}

impl FromStr for Rapid7HmacScheme {
    type Err = errors::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Rapid7HmacScheme {
            hash: s.to_owned()
        })
    }
}

impl Scheme for Rapid7HmacScheme {
    fn scheme() -> Option<&'static str> {
        Some("Rapid7-HMAC-V1-SHA256")
    }

    fn fmt_scheme(&self, f: &mut Formatter) -> std::result::Result<(), std::fmt::Error> {
        f.write_str(&self.hash)?;
        Ok(())
    }
}

fn auth_parse(unparsed: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let token: Vec<u8> = decode(unparsed).chain_err(|| format!("Failed to decode auth token: {}", unparsed))?;

    let mut split = token.splitn(2, |b| *b == b':');

    if let (Some(ident), Some(sig)) = (split.next(), split.next()) {
        let sig = base64::decode(&sig).chain_err(|| "")?;

        Ok((ident.to_vec(), sig.to_vec()))
    } else {
        bail!("Failed to parse Authentication token into a key and signature")
    }
}

fn get_digest(header: &hyper::header::Raw) -> Result<(Vec<u8>, Vec<u8>)> {
    if let Some(d) = header.one() {
        let mut split = d.splitn(2, |b| *b == b'=');
        if let (Some(algorithm), Some(digest)) = (split.next(), split.next()) {
            Ok((algorithm.to_vec(), digest.to_vec()))
        } else {
            bail!("Improperly formatted digest header")
        }
    } else {
        bail!("unexpected number of digest lines")
    }
}

fn client_err(err: &hyper::Error) -> (StatusCode, String) {
    use hyper::Error as HError;
    let bad_request = format!("{}", StatusCode::BadRequest);

    match *err {
        HError::Header => (StatusCode::BadRequest, json!({
                "Message": "An invalid `Header`.",
                "Name" : bad_request
            }).to_string()),
        HError::TooLarge => (StatusCode::BadRequest, json!({
                "Message": "A message head is too large to be reasonable.",
                "Name": bad_request
        }).to_string()),
        HError::Incomplete => (StatusCode::BadRequest, json!({
                "Message": "A message reached EOF, but is not complete.",
                "Name": bad_request
        }).to_string()),
        HError::Status => (StatusCode::InternalServerError, json!({
                "Message": "An invalid `Status`, such as `1337 ELITE`.",
                "Name": format!("{}", StatusCode::InternalServerError)
        }).to_string()),
        HError::Timeout => (StatusCode::GatewayTimeout, json!({
                "Message": "A timeout occurred waiting for an IO event.",
                "Name": format!("{}", StatusCode::GatewayTimeout)
        }).to_string()),
        HError::Io(ref e) => (StatusCode::InternalServerError, json!({
                "Message": format!("An `io::Error` that occurred while trying to read or write to a network stream. {}", e),
                "Name": format!("{}", StatusCode::InternalServerError)
        }).to_string()),
        HError::Utf8(ref e) => (StatusCode::BadRequest, json!({
                "Message": format!("Parsing a field as string failed {}", e),
                "Name": bad_request
        }).to_string()),
        // Method, Uri, and Version *must* be valid, we are just forwarding them along.
        HError::Method => (StatusCode::InternalServerError, json!({
                "Message": "Invalid Method",
                "Name": format!("{}", StatusCode::InternalServerError)
        }).to_string()),
        HError::Uri(ref u) => (StatusCode::InternalServerError, json!({
                "Message": format!("Invalid Uri. {}", u),
                "Name": format!("{}", StatusCode::InternalServerError)
        }).to_string()),
        HError::Version => (StatusCode::InternalServerError, json!({
                "Message": "Invalid HTTP Version",
                "Name": format!("{}", StatusCode::InternalServerError)
        }).to_string()),
        ref e => (StatusCode::BadRequest, json!({
                "Message": format!("Unknown error: {}", e),
                "Name": bad_request
        }).to_string())
    }
}

fn get_or_gen_correlation_id(headers: &hyper::Headers) -> Cow<[u8]> {
    if let Some(raw) = headers.get_raw("X-Request-Identifier") {
        if let Some(header) = raw.one() {
            return Cow::Borrowed(header)
        }
    }
    Cow::Owned(Uuid::new_v4().hyphenated().to_string().as_bytes().to_vec())
}

fn format_dest_url(uri: &hyper::Uri, scheme: &str) -> Result<hyper::Uri> {
    let scheme = uri.scheme().unwrap_or(scheme);
    let query = uri.query();

    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };

    let dest_url = if let Some(query) = query {
        format!("{}://{}{}?{}", scheme, LOCAL_SERVER, path, query)
    } else {
        format!("{}://{}{}", scheme, LOCAL_SERVER, path)
    };

    dest_url.parse().chain_err(|| format!("Could not parse dest_url: {}", dest_url))
}

fn body_from_auth_error<'a>(header_result: AuthorizationResult<'a>) -> String {
    let bad_request = format!("{}", StatusCode::BadRequest);

    match header_result {
        AuthorizationResult::UnAuthurized => json!({
            "Message":  "Failed to authorize - hmac validation failed",
            "Name":     bad_request,
        }).to_string(),
        AuthorizationResult::InvalidHeader(header) => json!({
            "Message":  format!("Invalid header - {}", header),
            "Name":     bad_request,
        }).to_string(),
        AuthorizationResult::UnsupportedAuthorizationScheme => json!({
            "Message":  "Unsupported AuthorizationScheme",
            "Name":     bad_request,
        }).to_string(),
        AuthorizationResult::UnsupportedDigest => json!({
            "Message":  "Unsupported Digest Algorithm",
            "Name":     bad_request,
        }).to_string(),
        AuthorizationResult::BodyReadFailure(ref e) => {
            let (_, err) = client_err(e);
            err
        }
        AuthorizationResult::MissingHeaders(headers) => {
            let headers = headers.join(", ");
            let mut buf = String::with_capacity("Missing headers: ".len() + headers.len());
            buf.push_str("Missing headers: ");
            buf.push_str(&headers);
            json!({
                "Message":  buf,
                "Name":     bad_request,
            }).to_string()
        }
        AuthorizationResult::SkewError => json!({
                "Message":  "Skew Error",
                "Name":     bad_request,
            }).to_string(),
    }
}

impl Service for Turnstile {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response, Error=hyper::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        let (client_method, client_uri, client_version, client_headers, client_body) = req.deconstruct();

        let mut metrics = Dog::with_chance(20);

        let res = validate_headers(metrics, self.logger.clone(), &client_method, &client_uri, &client_headers, client_body);

        let body = match res {
            Err(e) => {
                let body = body_from_auth_error(e);
                return Box::new(futures::future::ok(
                    Response::new()
                        .with_status(StatusCode::BadRequest)
                        .with_header(ContentType("application/json".parse().unwrap()))
                        .with_header(ContentLength(body.len() as u64))
                        .with_body(body)
                ))
            }
            Ok(body) => body
        };

        let request = self.gen_request(client_method, client_uri, client_version, client_headers, body);

        match request {
            Ok(request) => {
                Box::new(futures::future::ok(Box::new(self.client.request(request).then(|res| match res {
                    Ok(res) => {
                        Box::new(futures::future::ok(
                            Response::new()
                                .with_status(res.status())
                                .with_headers(res.headers().clone())
                                .with_body(res.body())
                        ))
                    }
                    Err(ref e) => {
                        let (code, err) = client_err(e);
                        Box::new(futures::future::ok(
                            Response::new()
                                .with_status(code)
                                .with_header(ContentType("application/json".parse().unwrap()))
                                .with_header(ContentLength(err.len() as u64))
                                .with_body(err)
                        ))
                    }
                }))))
            }
            Err(e) => {
                let body = json!({
                                "Message": "Could not generate downstream server request",
                                "Name": format!("{}", StatusCode::InternalServerError)
                                }).to_string();

                Box::new(futures::future::ok(
                    Response::new()
                        .with_status(StatusCode::InternalServerError)
                        .with_header(ContentType("application/json".parse().unwrap()))
                        .with_header(ContentLength(body.len() as u64))
                        .with_body(body)
                ))
            }

        }
//        unimplemented!()

//        Box::new(validate_headers(metrics, self.logger.clone(), client_method, client_uri, client_headers, client_body).then(|res| {
//            match res {
//                Err(e @ AuthorizationResult::InvalidHeader(_)) => {
//                    let body = body_from_auth_error(e);
//                    return Box::new(futures::future::err(
//                        Response::new()
//                            .with_status(StatusCode::BadRequest)
//                            .with_header(ContentType("application/json".parse().unwrap()))
//                            .with_header(ContentLength(body.len() as u64))
//                            .with_body(body)
//                    ))
//                }
//                Err(e @ AuthorizationResult::UnAuthurized) => {
//                    let body = body_from_auth_error(e);
//                    return Box::new(futures::future::err(
//                        Response::new()
//                            .with_status(StatusCode::Unauthorized)
//                            .with_header(ContentType("application/json".parse().unwrap()))
//                            .with_header(ContentLength(body.len() as u64))
//                            .with_body(body)
//                    ))
//                }
//                Err(e @ AuthorizationResult::SkewError) => {
//                    let body = body_from_auth_error(e);
//                    return Box::new(futures::future::err(
//                        Response::new()
//                            .with_status(StatusCode::Unauthorized)
//                            .with_header(ContentType("application/json".parse().unwrap()))
//                            .with_header(ContentLength(body.len() as u64))
//                            .with_body(body)
//                    ))
//                }
//                Err(e @ AuthorizationResult::MissingHeaders(_)) => {
//                    let body = body_from_auth_error(e);
//                    return Box::new(futures::future::err(
//                        Response::new()
//                            .with_status(StatusCode::BadRequest)
//                            .with_header(ContentType("application/json".parse().unwrap()))
//                            .with_header(ContentLength(body.len() as u64))
//                            .with_body(body)
//                    ))
//                }
//                Ok(body) => Box::new(futures::future::ok(body))
//            }
//        }).then(|res| {
//            match res {
//                Ok(body) => {
//                    let request = self.gen_request(client_method, client_uri, client_version, client_headers, body);
//
//                    match request {
//                        Ok(request) => {
//                            Box::new(futures::future::ok(Box::new(self.client.request(request).then(|res| match res {
//                                Ok(res) => {
//                                    futures::future::ok(
//                                        Response::new()
//                                            .with_status(res.status())
//                                            .with_headers(res.headers().clone())
//                                            .with_body(res.body())
//                                    )
//                                }
//                                Err(ref e) => {
//                                    let (code, err) = client_err(e);
//                                    futures::future::ok(
//                                        Response::new()
//                                            .with_status(code)
//                                            .with_header(ContentType("application/json".parse().unwrap()))
//                                            .with_header(ContentLength(err.len() as u64))
//                                            .with_body(err)
//                                    )
//                                }
//                            }))))
//                        }
//                        Err(e) => {
//                            let body = json!({
//                                "Message": "Could not generate downstream server request",
//                                "Name": format!("{}", StatusCode::InternalServerError)
//                                }).to_string();
//
//                            Box::new(futures::future::err(
//                                Response::new()
//                                    .with_status(StatusCode::InternalServerError)
//                                    .with_header(ContentType("application/json".parse().unwrap()))
//                                    .with_header(ContentLength(body.len() as u64))
//                                    .with_body(body)
//                            ))
//                        }
//
//                    }
//                },
//                Err(e) => {
//                    Box::new(futures::future::err(e))
//                }
//            }
//        }).map_err(|res| {
//            Box::new(futures::future::ok(res))
//        }))
    }
}

