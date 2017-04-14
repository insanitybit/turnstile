#![recursion_limit = "1024"]
#![deny(warnings)]

#[macro_use] extern crate slog;

extern crate slog_json;
extern crate slog_stream;

extern crate turnstilers;

extern crate clap;

extern crate base64;
extern crate futures;
extern crate hyper;
extern crate serde_json;
extern crate serde;
extern crate time;
extern crate tokio_core;
extern crate ring;
extern crate uuid;

use clap::{Arg, App};

use futures::{Stream, Future};

use hyper::Client;
use hyper::server::Http;

use tokio_core::net::TcpListener;

use std::io;
use slog::DrainExt;

use turnstilers::config::Config;
use turnstilers::turnstile::Turnstile;

fn main() {
    let matches = App::new("Turnstile")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Does awesome things")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .help("Sets a custom config file"))
        .get_matches();

    let d2 = slog_stream::async_stream(io::stdout(), slog_json::new().add_default_keys().build());
    let log = slog::Logger::root(d2.fuse(), o!("version" => env!("CARGO_PKG_VERSION")));

    let config = matches.value_of("config").map(Config::from_file).unwrap_or(Ok(Config::default())).unwrap();

    debug!(log, "Turnstile listening on: {}:{}", config.listen.bind, config.listen.port);

    let addr = config.listen.to_addr().expect("Invalid address");
    let secret = b"secret".to_vec();

    let mut core = tokio_core::reactor::Core::new().unwrap();
    let handle = core.handle();

    let listener = TcpListener::bind(&addr, &handle).unwrap();

    let http = Http::new();
    let client = Client::new(&core.handle());

    let server_handle = handle.clone();

    handle.spawn(listener.incoming().for_each(move |(sock, addr)| {
        http.bind_connection(&server_handle, sock, addr, Turnstile::new(client.clone(), secret.clone(), config.clone(), log.clone()));
        trace!(log, "Listening on http://{} with 1 thread.",
                 addr);
        futures::future::ok(())
    }).map_err(|_| ()));

    core.run(futures::future::empty::<(), ()>()).unwrap();
}
