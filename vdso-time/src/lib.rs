#![cfg_attr(any(not(feature = "std"), feature = "sgx"), no_std)]
#![feature(asm)]
#![feature(llvm_asm)]

#[cfg(feature = "sgx")]
extern crate sgx_types;
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;
#[cfg(feature = "sgx")]
extern crate sgx_libc as libc;

use atomic::{self, Atomic, Ordering};

mod sys;
use sys::*;

pub use sys::{ClockID, Timespec, Timeval, Timezone};

pub struct Vdso {
    vdso_data_ptr: VdsoDataPtr,
    coarse_resolution: Option<i64>,
}

impl Vdso {
    pub fn new(
        vdso_addr: u64,
        coarse_resolution: Option<i64>,
        kernel_version: (u8, u8),
    ) -> Result<Self, ()> {
        if vdso_addr == 0 {
            return Err(());
        }

        let vdso_data_ptr = match kernel_version {
            (5, 9) => {
                let vdso_data_addr = vdso_addr - 4 * PAGE_SIZE + 128;
                VdsoDataPtr::V5_9(vdso_data_addr as *const vdso_data_v5_9)
            }
            (_, _) => return Err(()),
        };

        Ok(Self {
            coarse_resolution,
            vdso_data_ptr,
        })
    }

    #[cfg(any(test, feature = "std", feature = "sgx"))]
    pub fn new_with_std() -> Result<Self, ()> {
        #[cfg(not(feature = "sgx"))]
        let (vdso_addr, coarse_resolution, release) = {
            const AT_SYSINFO_EHDR: u64 = 33;
            let vdso_addr = unsafe { libc::getauxval(AT_SYSINFO_EHDR) };

            let mut tp = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ret = unsafe {
                libc::clock_getres(ClockID::CLOCK_REALTIME_COARSE as _, &mut tp as *mut _)
            };
            let coarse_resolution = if ret == 0 { Some(tp.tv_nsec) } else { None };

            let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::uname(&mut utsname as *mut _) };
            if ret != 0 {
                return Err(());
            }

            (vdso_addr, coarse_resolution, utsname.release)
        };

        #[cfg(feature = "sgx")]
        let (vdso_addr, coarse_resolution, release) = {
            extern "C" {
                fn ocall_get_vdso_info(
                    ret: *mut libc::c_int,
                    vdso_addr: *mut libc::c_ulong,
                    coarse_resolution: *mut libc::c_long,
                    release: *mut libc::c_char,
                    release_len: libc::c_int,
                ) -> sgx_types::sgx_status_t;
            }

            let mut vdso_addr: libc::c_ulong = 0;
            let mut coarse_resolution: libc::c_long = 0;
            let mut release: [libc::c_char; 65] = [0; 65];
            let mut ret: libc::c_int = 0;
            unsafe {
                ocall_get_vdso_info(
                    &mut ret as *mut _,
                    &mut vdso_addr as *mut _,
                    &mut coarse_resolution as *mut _,
                    release.as_mut_ptr(),
                    release.len() as _,
                );
            }
            if ret != 0 {
                return Err(());
            }

            let coarse_resolution = if coarse_resolution != 0 {
                Some(coarse_resolution)
            } else {
                None
            };

            (vdso_addr, coarse_resolution, release)
        };

        // release, e.g., "5.9.6-050906-generic"
        // Then, kernel_version should be (5, 9)
        // if release is "5.10.1-...", kernel_version should be (5, 10)
        let kernel_version = if release[0] as u8 >= ('0' as u8)
            && release[0] as u8 <= ('9' as u8)
            && release[1] as u8 == ('.' as u8)
            && release[2] as u8 >= ('0' as u8)
            && release[2] as u8 <= ('9' as u8)
        {
            let big = release[0] as u8 - ('0' as u8);
            let little = release[2] as u8 - ('0' as u8);
            if release[3] as u8 == ('.' as u8) {
                (big, little)
            } else if release[3] as u8 >= ('0' as u8) && release[3] as u8 <= ('9' as u8) {
                let little = little * 10 + release[3] as u8 - ('0' as u8);
                (big, little)
            } else {
                return Err(());
            }
        } else {
            return Err(());
        };

        Self::new(vdso_addr, coarse_resolution, kernel_version)
    }

    // Linux time(): time_t time(time_t *tloc);
    pub fn time(&self, tloc: *mut i64) -> Result<i64, ()> {
        let vdso_data = self.vdso_data(ClockSource::CS_HRES_COARSE);
        let timestamp = vdso_data.vdso_timestamp(ClockID::CLOCK_REALTIME);
        let t: i64 = timestamp.sec as _;
        if !tloc.is_null() {
            unsafe {
                *tloc = t;
            }
        }
        Ok(t)
    }

    // Linux gettimeofday(): int gettimeofday(struct timeval *tv, struct timezone *tz);
    pub fn gettimeofday(&self, tv: *mut Timeval, tz: *mut Timezone) -> Result<i32, ()> {
        if !tv.is_null() {
            let mut tp = Timespec::default();
            self.do_hres(
                ClockSource::CS_HRES_COARSE,
                ClockID::CLOCK_REALTIME,
                &mut tp,
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
    pub fn clock_gettime(&self, clockid: ClockID, tp: &mut Timespec) -> Result<i32, ()> {
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
    pub fn clock_getres(&self, clockid: ClockID, res: &mut Timespec) -> Result<i32, ()> {
        let ns = match clockid {
            ClockID::CLOCK_REALTIME
            | ClockID::CLOCK_MONOTONIC
            | ClockID::CLOCK_BOOTTIME
            | ClockID::CLOCK_MONOTONIC_RAW => {
                let vdso_data = self.vdso_data(ClockSource::CS_HRES_COARSE);
                vdso_data.hrtimer_res() as i64
            }
            ClockID::CLOCK_REALTIME_COARSE | ClockID::CLOCK_MONOTONIC_COARSE => {
                if self.coarse_resolution.is_none() {
                    return Err(());
                }
                self.coarse_resolution.unwrap()
            }
            ClockID::CLOCK_PROCESS_CPUTIME_ID | ClockID::CLOCK_THREAD_CPUTIME_ID => return Err(()),
        };

        res.tv_sec = 0;
        res.tv_nsec = ns;
        Ok(0)
    }

    #[inline]
    fn vdso_data(&self, cs: ClockSource) -> &'static impl VdsoData {
        match self.vdso_data_ptr {
            VdsoDataPtr::V5_9(ptr) => unsafe { &*(ptr.add(cs as _)) },
        }
    }

    fn do_hres(&self, cs: ClockSource, clockid: ClockID, tp: &mut Timespec) -> Result<i32, ()> {
        let vdso_data = self.vdso_data(cs);
        let timestamp = vdso_data.vdso_timestamp(clockid);
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
                    llvm_asm!("rdtscp"
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
                tp.tv_sec = (sec + ns / NSEC_PER_SEC) as i64;
                tp.tv_nsec = (ns % NSEC_PER_SEC) as i64;
                break;
            }
        }
        Ok(0)
    }

    fn do_coarse(&self, cs: ClockSource, clockid: ClockID, tp: &mut Timespec) -> Result<i32, ()> {
        let vdso_data = self.vdso_data(cs);
        let timestamp = vdso_data.vdso_timestamp(clockid);
        loop {
            let seq = vdso_data.seq();

            atomic::fence(Ordering::Acquire);

            tp.tv_sec = timestamp.sec as i64;
            tp.tv_nsec = timestamp.nsec as i64;

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
    const USEC_PER_SEC: u64 = 1000000;
    const MAX_DIFF_NSEC: u64 = 2000;

    #[test]
    fn test_time() {
        let vdso = Vdso::new_with_std().unwrap();
        for _ in 0..LOOPS {
            let mut vdso_tloc: i64 = 0;
            let vdso_time = vdso.time(&mut vdso_tloc as *mut _).unwrap();
            let libc_time = unsafe { libc::time(std::ptr::null_mut()) };
            println!(
                "[time()] vdso: {}, libc: {}, diff: {}",
                vdso_time,
                libc_time,
                libc_time - vdso_time
            );
            assert_eq!(vdso_time, libc_time);
            assert_eq!(vdso_time, vdso_tloc);

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
        let vdso = Vdso::new_with_std().unwrap();
        for _ in 0..LOOPS {
            let mut vdso_tp = Timespec::default();
            let mut libc_tp = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            vdso.clock_gettime(clockid, &mut vdso_tp).unwrap();

            unsafe { libc::clock_gettime(clockid as _, &mut libc_tp as *mut _) };

            let diff = (libc_tp.tv_sec - vdso_tp.tv_sec) * NSEC_PER_SEC as i64
                + (libc_tp.tv_nsec - vdso_tp.tv_nsec);

            println!(
                "[clock_gettime({:?})], vdso: [ tv_sec {}, tv_nsec {} ], libc: [ tv_sec {}, tv_nsec {} ], diff: {} nsec",
                clockid, vdso_tp.tv_sec, vdso_tp.tv_nsec, libc_tp.tv_sec, libc_tp.tv_nsec, diff,
            );
            assert!(diff >= 0 && diff <= MAX_DIFF_NSEC as i64);

            let ten_millis = time::Duration::from_millis(SLEEP_DURATION);
            thread::sleep(ten_millis);
        }
    }

    #[test]
    fn test_gettimeofday() {
        let vdso = Vdso::new_with_std().unwrap();
        for _ in 0..LOOPS {
            let mut vdso_tv = Timeval::default();
            let mut vdso_tz = Timezone::default();
            let mut libc_tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            let mut libc_tz = Timezone::default();

            vdso.gettimeofday(&mut vdso_tv as *mut _, &mut vdso_tz as *mut _)
                .unwrap();

            unsafe {
                libc::gettimeofday(
                    &mut libc_tv as *mut _,
                    &mut libc_tz as *mut Timezone as *mut _,
                )
            };

            let diff = (libc_tv.tv_sec - vdso_tv.tv_sec) * USEC_PER_SEC as i64
                + (libc_tv.tv_usec - vdso_tv.tv_usec);

            println!(
                "[gettimeofday()], vdso: [ tv_sec {}, tv_usec {} ], libc: [ tv_sec {}, tv_usec {} ], diff: {} nsec",
                vdso_tv.tv_sec, vdso_tv.tv_usec, libc_tv.tv_sec, libc_tv.tv_usec, diff,
            );
            assert!(diff >= 0 && diff <= (MAX_DIFF_NSEC / NSEC_PER_USEC) as i64);
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
        let vdso = Vdso::new_with_std().unwrap();
        for _ in 0..LOOPS {
            let mut vdso_tp = Timespec::default();
            let mut libc_tp = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            vdso.clock_getres(clockid, &mut vdso_tp).unwrap();

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
