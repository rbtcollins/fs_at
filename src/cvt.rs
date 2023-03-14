//! This package exposes the `cvt` function used extensively by `libstd` to
//! convert platform-specific syscall error codes to `std::io::Result`.
//!
//! Usually syscalls use return values for errors, the conventions differ. For instance,
//! on Unix `0` usually means success on Unix but failure on Windows.
//! While those conventions are not always followed, they usually are and
//! `cvt` is there to reduce the mental bookkeeping and make it easier to handle syscall errors.
//!
//! The code was mostly copied over from Rust libstd, because the function is not public.

cfg_if::cfg_if! {
    if #[cfg(target_os = "vxworks")] {
        mod vxworks;
        pub use self::vxworks::{cvt, cvt_r};
    } else if #[cfg(unix)] {
        mod unix;
        pub use self::unix::{cvt, cvt_r};
    } else if #[cfg(windows)] {
        mod windows;
        pub use self::windows::cvt;
    } else {
        compile_error!("cvt doesn't compile for this platform yet");
    }
}
