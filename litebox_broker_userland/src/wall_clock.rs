// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host wall-clock time for userland brokers.

use std::time::{Duration, SystemTime};

use litebox_broker_core::fs::{FileTime, WallClockProvider};

/// Reads the host operating system's wall clock.
pub struct UserlandWallClockProvider;

impl WallClockProvider for UserlandWallClockProvider {
    fn now(&self) -> FileTime {
        file_time(SystemTime::now())
    }
}

/// `time` as a [`FileTime`], saturating at the limits of its range.
pub(crate) fn file_time(time: SystemTime) -> FileTime {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => FileTime {
            seconds: i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
            nanoseconds: since.subsec_nanos(),
        },
        Err(before) => {
            // Count whole seconds back from the epoch, then nanoseconds forward again.
            let until = before.duration();
            let seconds = i64::try_from(until.as_secs()).map_or(i64::MIN, |seconds| -seconds);
            match until.subsec_nanos() {
                0 => FileTime {
                    seconds,
                    nanoseconds: 0,
                },
                nanoseconds => FileTime {
                    seconds: seconds.saturating_sub(1),
                    nanoseconds: FileTime::NANOSECONDS_PER_SECOND - nanoseconds,
                },
            }
        }
    }
}

/// `time` as a [`SystemTime`], if the host can represent it.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) fn system_time(time: FileTime) -> Option<SystemTime> {
    let seconds = Duration::from_secs(time.seconds.unsigned_abs());
    let whole = if time.seconds < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(seconds)
    } else {
        SystemTime::UNIX_EPOCH.checked_add(seconds)
    }?;
    whole.checked_add(Duration::from_nanos(time.nanoseconds.into()))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod tests {
    use super::*;

    #[test]
    fn converts_times_on_both_sides_of_the_epoch() {
        // Whole multiples of 100 ns, which is as precise as Windows gets.
        for time in [
            FileTime::EPOCH,
            FileTime {
                seconds: 1_700_000_000,
                nanoseconds: 123_456_700,
            },
            FileTime {
                seconds: -1,
                nanoseconds: 999_999_900,
            },
            FileTime {
                seconds: -2,
                nanoseconds: 100,
            },
            FileTime {
                seconds: -86_400,
                nanoseconds: 0,
            },
        ] {
            assert_eq!(file_time(system_time(time).unwrap()), time);
        }
        assert_eq!(
            system_time(FileTime {
                seconds: -1,
                nanoseconds: 500_000_000,
            }),
            SystemTime::UNIX_EPOCH.checked_sub(Duration::from_millis(500)),
        );
    }
}
