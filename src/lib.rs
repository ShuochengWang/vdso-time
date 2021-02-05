#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#![feature(asm)]
#![feature(llvm_asm)]

// #[cfg(feature = "sgx_std")]
// #[macro_use]
// extern crate sgx_tstd as std;

use atomic::{self, Atomic, Ordering};
use core::ptr::NonNull;

mod sys;
use sys::*;

pub struct Vdso {
    vdso_addr: u64,
    coarse_resolution: Option<u32>,
}

impl Vdso {
    pub fn new(vdso_addr: u64, coarse_resolution: Option<u32>) -> Self {
        assert!(vdso_addr != 0);
        Self {
            vdso_addr,
            coarse_resolution,
        }
    }

    #[cfg(any(test, feature = "std"))]
    pub fn new_with_std() -> Self {
        const AT_SYSINFO_EHDR: u64 = 33;
        let vdso_addr = unsafe { libc::getauxval(AT_SYSINFO_EHDR) };

        let mut tp = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_getres(ClockID::CLOCK_REALTIME_COARSE as _, &mut tp as *mut _) };
        let coarse_resolution = Some(tp.tv_nsec as u32);
        Self::new(vdso_addr, coarse_resolution)
    }

    // Linux time(): time_t time(time_t *tloc);
    pub fn time(&self, tloc: *mut time_t) -> Result<time_t, ()> {
        let vdso_data = self.vdso_data(ClockSource::CS_HRES_COARSE);
        let timestamp = vdso_data.vdso_timestamp(ClockID::CLOCK_REALTIME);
        let t: time_t = timestamp.sec as _;
        if !tloc.is_null() {
            unsafe {
                *tloc = t;
            }
        }
        Ok(t)
    }

    // Linux gettimeofday(): int gettimeofday(struct timeval *tv, struct timezone *tz);
    pub fn gettimeofday(&self, tv: *mut timeval, tz: *mut timezone) -> Result<i32, ()> {
        if !tv.is_null() {
            let mut tp = timespec::default();
            self.do_hres(
                ClockSource::CS_HRES_COARSE,
                ClockID::CLOCK_REALTIME,
                NonNull::new(&mut tp as *mut _).unwrap(),
            )?;
            unsafe {
                (*tv).tv_sec = tp.tv_sec;
                (*tv).tv_usec = tp.tv_nsec / NSEC_PER_USEC as i64;
            }
        }

        if !tz.is_null() {
            let vdso_data = self.vdso_data(ClockSource::CS_HRES_COARSE);
            unsafe {
                (*tz).tz_minuteswest = vdso_data.tz_minuteswest();
                (*tz).tz_dsttime = vdso_data.tz_dsttime();
            }
        }

        Ok(0)
    }

    // Linux clock_gettime(): int clock_gettime(clockid_t clockid, struct timespec *tp);
    pub fn clock_gettime(&self, clockid: ClockID, tp: NonNull<timespec>) -> Result<i32, ()> {
        match clockid {
            ClockID::CLOCK_REALTIME | ClockID::CLOCK_MONOTONIC | ClockID::CLOCK_BOOTTIME => {
                self.do_hres(ClockSource::CS_HRES_COARSE, clockid, tp)
            }
            ClockID::CLOCK_MONOTONIC_RAW => self.do_hres(ClockSource::CS_RAW, clockid, tp),
            ClockID::CLOCK_REALTIME_COARSE | ClockID::CLOCK_MONOTONIC_COARSE => {
                self.do_coarse(ClockSource::CS_HRES_COARSE, clockid, tp)
            }
            ClockID::CLOCK_PROCESS_CPUTIME_ID | ClockID::CLOCK_THREAD_CPUTIME_ID => Err(()),
        }
    }

    // Linux clock_getres(): int clock_getres(clockid_t clockid, struct timespec *res);
    pub fn clock_getres(&self, clockid: ClockID, res: NonNull<timespec>) -> Result<i32, ()> {
        let ns = match clockid {
            ClockID::CLOCK_REALTIME
            | ClockID::CLOCK_MONOTONIC
            | ClockID::CLOCK_BOOTTIME
            | ClockID::CLOCK_MONOTONIC_RAW => {
                let vdso_data = self.vdso_data(ClockSource::CS_HRES_COARSE);
                vdso_data.hrtimer_res()
            }
            ClockID::CLOCK_REALTIME_COARSE | ClockID::CLOCK_MONOTONIC_COARSE => {
                if self.coarse_resolution.is_none() {
                    return Err(());
                }
                self.coarse_resolution.unwrap()
            }
            ClockID::CLOCK_PROCESS_CPUTIME_ID | ClockID::CLOCK_THREAD_CPUTIME_ID => return Err(()),
        };

        let res = res.as_ptr();
        unsafe {
            (*res).tv_sec = 0;
            (*res).tv_nsec = ns as i64;
        }
        Ok(0)
    }

    #[inline]
    fn vdso_data(&self, cs: ClockSource) -> &'static impl VdsoData {
        let vdso_data_addr = self.vdso_addr - 4 * PAGE_SIZE + 128;
        let vdso_data_ptr = vdso_data_addr as *const vdso_data_v5_9;
        unsafe { &*(vdso_data_ptr.add(cs as _)) }
    }

    fn do_hres(&self, cs: ClockSource, clockid: ClockID, tp: NonNull<timespec>) -> Result<i32, ()> {
        let vdso_data = self.vdso_data(cs);
        let timestamp = vdso_data.vdso_timestamp(clockid);
        let tp = tp.as_ptr();
        loop {
            let seq = vdso_data.seq();

            atomic::fence(Ordering::Acquire);

            if vdso_data.clock_mode() == vdso_clock_mode::VDSO_CLOCKMODE_NONE as i32 {
                return Err(());
            }

            let cycles = {
                let upper: u64;
                let lower: u64;
                unsafe {
                    llvm_asm!("rdtsc"
                         : "={rax}"(lower),
                           "={rdx}"(upper)
                         :
                         :
                         : "volatile"
                    );
                }
                upper << 32 | lower
            };

            let sec = timestamp.sec;
            let mut ns = timestamp.nsec;
            ns += ((cycles - vdso_data.cycle_last()) & vdso_data.mask()) * vdso_data.mult() as u64;
            ns = ns >> vdso_data.shift();

            if !Self::vdso_read_retry(vdso_data, seq) {
                unsafe {
                    (*tp).tv_sec = (sec + ns / NSEC_PER_SEC) as i64;
                    (*tp).tv_nsec = (ns % NSEC_PER_SEC) as i64;
                }
                break;
            }
        }
        Ok(0)
    }

    fn do_coarse(
        &self,
        cs: ClockSource,
        clockid: ClockID,
        tp: NonNull<timespec>,
    ) -> Result<i32, ()> {
        let vdso_data = self.vdso_data(cs);
        let timestamp = vdso_data.vdso_timestamp(clockid);
        let tp = tp.as_ptr();
        loop {
            let seq = vdso_data.seq();

            atomic::fence(Ordering::Acquire);

            unsafe {
                (*tp).tv_sec = timestamp.sec as i64;
                (*tp).tv_nsec = timestamp.nsec as i64;
            }

            if !Self::vdso_read_retry(vdso_data, seq) {
                break;
            }
        }
        Ok(0)
    }

    #[inline]
    fn vdso_read_retry(vdso_data: &impl VdsoData, old_seq: u32) -> bool {
        atomic::fence(Ordering::Acquire);
        old_seq != vdso_data.seq()
    }
}

// All unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time};

    const LOOPS: usize = 3;
    const SLEEP_DURATION: u64 = 10;

    #[test]
    fn test_time() {
        let vdso = Vdso::new_with_std();
        for _ in 0..LOOPS {
            let vdso_time = vdso.time(std::ptr::null_mut()).unwrap();
            let libc_time = unsafe { libc::time(std::ptr::null_mut()) };
            println!(
                "[time()] vdso: {}, libc: {}, diff: {}",
                vdso_time,
                libc_time,
                libc_time - vdso_time
            );
            assert_eq!(vdso_time, libc_time);

            let ten_millis = time::Duration::from_millis(SLEEP_DURATION);
            thread::sleep(ten_millis);
        }
    }

    #[test]
    fn test_clock_gettime() {
        test_single_clock_gettime(ClockID::CLOCK_REALTIME_COARSE);
        test_single_clock_gettime(ClockID::CLOCK_MONOTONIC_COARSE);
        test_single_clock_gettime(ClockID::CLOCK_REALTIME);
        test_single_clock_gettime(ClockID::CLOCK_MONOTONIC);
        test_single_clock_gettime(ClockID::CLOCK_BOOTTIME);
        test_single_clock_gettime(ClockID::CLOCK_MONOTONIC_RAW);
    }

    fn test_single_clock_gettime(clockid: ClockID) {
        let vdso = Vdso::new_with_std();
        for _ in 0..LOOPS {
            let mut vdso_tp = timespec::default();
            let mut libc_tp = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            vdso.clock_gettime(clockid, NonNull::new(&mut vdso_tp as *mut _).unwrap())
                .unwrap();

            unsafe { libc::clock_gettime(clockid as _, &mut libc_tp as *mut _) };

            let diff = (libc_tp.tv_sec - vdso_tp.tv_sec) * NSEC_PER_SEC as i64
                + (libc_tp.tv_nsec - vdso_tp.tv_nsec);

            println!(
                "[clock_gettime({:?})], vdso: [ tv_sec {}, tv_nsec {} ], libc: [ tv_sec {}, tv_nsec {} ], diff: {} nsec",
                clockid, vdso_tp.tv_sec, vdso_tp.tv_nsec, libc_tp.tv_sec, libc_tp.tv_nsec, diff,
            );
            assert!(diff < 2000);

            let ten_millis = time::Duration::from_millis(SLEEP_DURATION);
            thread::sleep(ten_millis);
        }
    }

    #[test]
    fn test_gettimeofday() {
        let vdso = Vdso::new_with_std();
        for _ in 0..LOOPS {
            let mut vdso_tv = timeval::default();
            let mut vdso_tz = timezone::default();
            let mut libc_tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            let mut libc_tz = timezone::default();

            vdso.gettimeofday(&mut vdso_tv as *mut _, &mut vdso_tz as *mut _)
                .unwrap();

            unsafe {
                libc::gettimeofday(
                    &mut libc_tv as *mut _,
                    &mut libc_tz as *mut timezone as *mut _,
                )
            };

            let diff = (libc_tv.tv_sec - vdso_tv.tv_sec) * USEC_PER_SEC as i64
                + (libc_tv.tv_usec - vdso_tv.tv_usec);

            println!(
                "[gettimeofday()], vdso: [ tv_sec {}, tv_usec {} ], libc: [ tv_sec {}, tv_usec {} ], diff: {} nsec",
                vdso_tv.tv_sec, vdso_tv.tv_usec, libc_tv.tv_sec, libc_tv.tv_usec, diff,
            );
            assert!(diff < 1000);
            assert_eq!(vdso_tz.tz_minuteswest, libc_tz.tz_minuteswest);
            assert_eq!(vdso_tz.tz_dsttime, libc_tz.tz_dsttime);

            let ten_millis = time::Duration::from_millis(SLEEP_DURATION);
            thread::sleep(ten_millis);
        }
    }

    #[test]
    fn test_clock_getres() {
        test_single_clock_getres(ClockID::CLOCK_REALTIME_COARSE);
        test_single_clock_getres(ClockID::CLOCK_MONOTONIC_COARSE);
        test_single_clock_getres(ClockID::CLOCK_REALTIME);
        test_single_clock_getres(ClockID::CLOCK_MONOTONIC);
        test_single_clock_getres(ClockID::CLOCK_BOOTTIME);
        test_single_clock_getres(ClockID::CLOCK_MONOTONIC_RAW);
    }

    fn test_single_clock_getres(clockid: ClockID) {
        let vdso = Vdso::new_with_std();
        for _ in 0..LOOPS {
            let mut vdso_tp = timespec::default();
            let mut libc_tp = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            vdso.clock_getres(clockid, NonNull::new(&mut vdso_tp as *mut _).unwrap())
                .unwrap();

            unsafe { libc::clock_getres(clockid as _, &mut libc_tp as *mut _) };

            println!(
                "[clock_getres({:?})], vdso: [ tv_sec {}, tv_nsec {} ], libc: [ tv_sec {}, tv_nsec {} ]",
                clockid, vdso_tp.tv_sec, vdso_tp.tv_nsec, libc_tp.tv_sec, libc_tp.tv_nsec,
            );
            assert_eq!(vdso_tp.tv_sec, libc_tp.tv_sec);
            assert_eq!(vdso_tp.tv_nsec, libc_tp.tv_nsec);
        }
    }
}
