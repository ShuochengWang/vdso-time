# vdso-time
A rust crate for getting time using vDSO. This crate can support host (std or no_std) and SGX (based on Rust-SGX-SDK).

## Quick Start
```
// clone vdso-time repo.
cd vdso-time/third_parties
git clone https://github.com/apache/incubator-teaclave-sgx-sdk.git
cd incubator-teaclave-sgx-sdk
git checkout d94996

// test
cd ../../vdso-time
cargo t --release --tests
cargo run --example example
cd examples/sgx && make && cd bin && ./app
```

## Getting Started
Add the following dependency to your Cargo manifest:

```
vdso-time = { path = "yourpath/vdso-time" }
```

If you want to use in SGX environment, add the following dependency to your Cargo manifest:

```
vdso-time = { path = "yourpath/vdso-time", default-features = false, features = ["sgx"] }
```

## API examples

```
use vdso_time::{ClockID, Timespec, Timeval, Timezone, Vdso};

// init vdso
let vdso = Vdso::new_with_std().unwrap();

// time()
let mut tloc: i64 = 0;
let time = vdso.time(&mut tloc as *mut _).unwrap();
println!("time(): t {}, tloc {}", time, tloc);

// gettimeofday()
let mut tv = Timeval::default();
let mut tz = Timezone::default();
vdso.gettimeofday(&mut tv as *mut _, &mut tz as *mut _)
    .unwrap();
println!(
    "gettimeofday(): tv_sec {}, tv_usec {}; tz_minuteswest {}, tz_dsttime {}",
    tv.tv_sec, tv.tv_usec, tz.tz_minuteswest, tz.tz_dsttime,
);

// clock_gettime()
let mut tp = Timespec::default();
let clockid = ClockID::CLOCK_REALTIME;
vdso.clock_gettime(clockid, &mut tp).unwrap();
println!(
    "clock_gettime({:?}): tv_sec {}, tv_nsec {}",
    clockid, tp.tv_sec, tp.tv_nsec
);

// clock_getres()
let mut tp = Timespec::default();
let clockid = ClockID::CLOCK_REALTIME;
vdso.clock_getres(clockid, &mut tp).unwrap();
println!(
    "clock_getres({:?}): tv_sec {}, tv_nsec {}",
    clockid, tp.tv_sec, tp.tv_nsec
);
```