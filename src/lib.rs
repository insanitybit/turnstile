#![feature(conservative_impl_trait)]
#![cfg_attr(feature = "unstable", feature(test))]
#![recursion_limit = "1024"]

#![allow(unused_features)]
#![allow(warnings)]

#[macro_use] extern crate error_chain;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate slog;

extern crate slog_json;
extern crate slog_stream;

extern crate base64;
extern crate clap;
extern crate dogstatsd;
extern crate futures;
extern crate hyper;
extern crate ring;
extern crate serde;
extern crate time;
extern crate tokio_core;
extern crate uuid;
extern crate xorshift;

pub mod config;
pub mod errors;
pub mod turnstile;
pub mod metrics;
