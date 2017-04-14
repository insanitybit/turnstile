use std::borrow::Cow;
use dogstatsd::{Client, Options, DogstatsdResult};
use xorshift::xoroshiro128::Xoroshiro128;
use xorshift::{Rng, SeedableRng};


pub struct DroppingMetrics {
    client: Client,
    prng: Xoroshiro128,
    chance: u32
}

impl DroppingMetrics {
    pub fn with_chance(chance: u32) -> DroppingMetrics {
        DroppingMetrics {
            client: Client::new(Options::default()),
            prng: Xoroshiro128::from_seed(&[481345754190446, 22956618888, 952505546299]),
            chance: chance
        }
    }

    pub fn incr<'a, S: Into<Cow<'a, str>>>(&mut self, stat: S, tags: &[&str]) -> DogstatsdResult {
        if self.prng.gen_weighted_bool(self.chance) {
            self.client.incr(stat, tags)
        } else {
            Ok(())
        }
    }
    pub fn decr<'a, S: Into<Cow<'a, str>>>(&mut self, stat: S, tags: &[&str]) -> DogstatsdResult {
        if self.prng.gen_weighted_bool(self.chance) {
            self.client.decr(stat, tags)
        } else {
            Ok(())
        }
    }
    pub fn time<'a, S: Into<Cow<'a, str>>, F: FnOnce()>(&mut self, stat: S, tags: &[&str], block: F) -> DogstatsdResult {
        if self.prng.gen_weighted_bool(self.chance) {
            self.client.time(stat, tags, block)
        } else {
            Ok(())
        }
    }
    pub fn timing<'a, S: Into<Cow<'a, str>>>(&mut self, stat: S, ms: i64, tags: &[&str]) -> DogstatsdResult {
        if self.prng.gen_weighted_bool(self.chance) {
            self.client.timing(stat, ms, tags)
        } else {
            Ok(())
        }
    }
    pub fn gauge<'a, S: Into<Cow<'a, str>>>(&mut self, stat: S, val: S, tags: &[&str]) -> DogstatsdResult {
        if self.prng.gen_weighted_bool(self.chance) {
            self.client.gauge(stat, val, tags)
        } else {
            Ok(())
        }
    }
    pub fn histogram<'a, S: Into<Cow<'a, str>>>(&mut self, stat: S, val: S, tags: &[&str]) -> DogstatsdResult {
        if self.prng.gen_weighted_bool(self.chance) {
            self.client.histogram(stat, val, tags)
        } else {
            Ok(())
        }
    }
    pub fn set<'a, S: Into<Cow<'a, str>>>(&mut self, stat: S, val: S, tags: &[&str]) -> DogstatsdResult {
        if self.prng.gen_weighted_bool(self.chance) {
            self.client.set(stat, val, tags)
        } else {
            Ok(())
        }
    }
    pub fn event<'a, S: Into<Cow<'a, str>>>(&mut self, title: S, text: S, tags: &[&str]) -> DogstatsdResult {
        if self.prng.gen_weighted_bool(self.chance) {
            self.client.event(title, text, tags)
        } else {
            Ok(())
        }
    }
}

#[cfg(all(feature = "unstable", test))]
mod bench {
    extern crate test;

    use self::test::Bencher;
    use super::*;

    #[bench]
    fn bench_incr(b: &mut Bencher) {
        let mut metrics = DroppingMetrics::with_chance(20);
        let tags = &["name1:value1"];
        b.iter(|| {
            metrics.incr("bench.incr", tags).unwrap();
        })
    }

    #[bench]
    fn bench_decr(b: &mut Bencher) {
        let mut metrics = DroppingMetrics::with_chance(20);
        let tags = &["name1:value1"];
        b.iter(|| {
            metrics.decr("bench.decr", tags).unwrap();
        })
    }

    #[bench]
    fn bench_timing(b: &mut Bencher) {
        let mut metrics = DroppingMetrics::with_chance(20);
        let tags = &["name1:value1"];
        let mut i = 0;
        b.iter(|| {
            metrics.timing("bench.timing", i, tags).unwrap();
            i += 1;
        })
    }

    #[bench]
    fn bench_gauge(b: &mut Bencher) {
        let mut metrics = DroppingMetrics::with_chance(20);
        let tags = vec!["name1:value1"];
        let mut i = 0;
        b.iter(|| {
            metrics.gauge("bench.timing", &i.to_string(), &tags).unwrap();
            i += 1;
        })
    }

    #[bench]
    fn bench_histogram(b: &mut Bencher) {
        let mut metrics = DroppingMetrics::with_chance(20);
        let tags = vec!["name1:value1"];
        let mut i = 0;
        b.iter(|| {
            metrics.histogram("bench.timing", &i.to_string(), &tags).unwrap();
            i += 1;
        })
    }

    #[bench]
    fn bench_set(b: &mut Bencher) {
        let mut metrics = DroppingMetrics::with_chance(20);
        let tags = vec!["name1:value1"];
        let mut i = 0;
        b.iter(|| {
            metrics.set("bench.timing", &i.to_string(), &tags).unwrap();
            i += 1;
        })
    }

    #[bench]
    fn bench_event(b: &mut Bencher) {
        let mut metrics = DroppingMetrics::with_chance(20);
        let tags = vec!["name1:value1"];
        b.iter(|| {
            metrics.event("Test Event Title", "Test Event Message", &tags).unwrap();
        })
    }
}
