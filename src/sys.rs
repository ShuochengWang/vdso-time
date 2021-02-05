use super::*;

pub const PAGE_SIZE: u64 = 4096;

pub const CLOCK_TAI: usize = 11;
pub const VDSO_BASES: usize = CLOCK_TAI + 1;

// pub const MSEC_PER_SEC: u64 = 1000;
// pub const USEC_PER_MSEC: u64 = 1000;
pub const NSEC_PER_USEC: u64 = 1000;
pub const USEC_PER_SEC: u64 = 1000000;
pub const NSEC_PER_SEC: u64 = 1000000000;

/// The timers is divided in 3 sets (HRES, COARSE, RAW),
/// CS_HRES_COARSE refers to the first two and CS_RAW to the third.
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum ClockSource {
    CS_HRES_COARSE = 0,
    CS_RAW = 1,
}

#[allow(non_camel_case_types)]
pub type time_t = i64;
#[allow(non_camel_case_types)]
pub type suseconds_t = i64;
// #[allow(non_camel_case_types)]
// pub type clock_t = i64;
#[allow(non_camel_case_types)]
pub type clockid_t = i32;

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum ClockID {
    CLOCK_REALTIME = 0,
    CLOCK_MONOTONIC = 1,
    CLOCK_PROCESS_CPUTIME_ID = 2,
    CLOCK_THREAD_CPUTIME_ID = 3,
    CLOCK_MONOTONIC_RAW = 4,
    CLOCK_REALTIME_COARSE = 5,
    CLOCK_MONOTONIC_COARSE = 6,
    CLOCK_BOOTTIME = 7,
}

impl ClockID {
    #[deny(unreachable_patterns)]
    pub fn from_raw(clockid: clockid_t) -> Result<ClockID, ()> {
        Ok(match clockid as i32 {
            0 => ClockID::CLOCK_REALTIME,
            1 => ClockID::CLOCK_MONOTONIC,
            2 => ClockID::CLOCK_PROCESS_CPUTIME_ID,
            3 => ClockID::CLOCK_THREAD_CPUTIME_ID,
            4 => ClockID::CLOCK_MONOTONIC_RAW,
            5 => ClockID::CLOCK_REALTIME_COARSE,
            6 => ClockID::CLOCK_MONOTONIC_COARSE,
            7 => ClockID::CLOCK_BOOTTIME,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum vdso_clock_mode {
    VDSO_CLOCKMODE_NONE = 0,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct timespec {
    pub tv_sec: time_t, /* seconds */
    pub tv_nsec: i64,   /* nanoseconds */
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct timeval {
    pub tv_sec: time_t,       /* seconds */
    pub tv_usec: suseconds_t, /* microseconds */
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct timezone {
    pub tz_minuteswest: i32, /* Minutes west of GMT.  */
    pub tz_dsttime: i32,     /* Nonzero if DST is ever in effect.  */
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct arch_vdso_data {}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct vdso_timestamp {
    pub sec: u64,
    pub nsec: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct timens_offset {
    pub sec: i64,
    pub nsec: u64,
}

pub trait VdsoData {
    fn vdso_timestamp(&self, clockid: ClockID) -> &vdso_timestamp;
    fn seq(&self) -> u32;
    fn clock_mode(&self) -> i32;
    fn cycle_last(&self) -> u64;
    fn mask(&self) -> u64;
    fn mult(&self) -> u32;
    fn shift(&self) -> u32;
    fn tz_minuteswest(&self) -> i32;
    fn tz_dsttime(&self) -> i32;
    fn hrtimer_res(&self) -> u32;
}

#[repr(C)]
pub struct vdso_data_v5_9 {
    pub seq: Atomic<u32>,

    pub clock_mode: i32,
    pub cycle_last: u64,
    pub mask: u64,
    pub mult: u32,
    pub shift: u32,

    pub union_1: vdso_data_union_1,

    pub tz_minuteswest: i32,
    pub tz_dsttime: i32,
    pub hrtimer_res: u32,
    pub __unused: u32,

    pub arch_data: arch_vdso_data,
}

impl VdsoData for vdso_data_v5_9 {
    #[inline]
    fn vdso_timestamp(&self, clockid: ClockID) -> &vdso_timestamp {
        unsafe { &self.union_1.basetime[clockid as usize] }
    }

    #[inline]
    fn seq(&self) -> u32 {
        self.seq.load(Ordering::Acquire)
    }

    #[inline]
    fn clock_mode(&self) -> i32 {
        self.clock_mode
    }

    #[inline]
    fn cycle_last(&self) -> u64 {
        self.cycle_last
    }

    #[inline]
    fn mask(&self) -> u64 {
        self.mask
    }

    #[inline]
    fn mult(&self) -> u32 {
        self.mult
    }

    #[inline]
    fn shift(&self) -> u32 {
        self.shift
    }

    #[inline]
    fn tz_minuteswest(&self) -> i32 {
        self.tz_minuteswest
    }

    #[inline]
    fn tz_dsttime(&self) -> i32 {
        self.tz_dsttime
    }

    #[inline]
    fn hrtimer_res(&self) -> u32 {
        self.hrtimer_res
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union vdso_data_union_1 {
    pub basetime: [vdso_timestamp; VDSO_BASES],
    pub offset: [timens_offset; VDSO_BASES],
}
