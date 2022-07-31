use std::{
    fs::File,
    io::Result,
    os::unix::prelude::{AsRawFd, FromRawFd},
    path::Path,
};

// This will probably take a few iterations to get right. The idea: always use
// an openat64, and import the right variant for the platform. See File::open_c in [`std::sys::unix::fs`].
cfg_if::cfg_if! {
    if #[cfg(target_os="macos")] {
        use libc::openat as openat64;
    } else {
        use libc::openat64;
    }
}

use cvt::cvt_r;
use libc::{c_int, mkdirat, mode_t};

use crate::OpenOptions;

pub mod exports {
    pub use super::OpenOptionsExt;
    #[doc(no_inline)]
    pub use libc::mode_t;
}

struct CString(std::ffi::CString);

impl TryFrom<&Path> for CString {
    type Error = std::io::Error;

    fn try_from(value: &Path) -> std::result::Result<Self, Self::Error> {
        // This is messy and probably needs a revisit.
        // Path is an OsStr
        Ok(CString(std::ffi::CString::new(
            value.as_os_str().to_str().unwrap(),
        )?))
    }
}

#[derive(Debug, Default)]
pub(crate) struct OpenOptionsImpl {
    mode: Option<mode_t>,
}

impl OpenOptionsImpl {
    /// One note: as the widespread unix interfaces don't offer atomic
    /// create-and-open, there is a race condition here (which is bad as this
    /// crate exists to target race conditions). Possibly addressable by a
    /// create-random + atomic move into place, but it isn't clear that this
    /// interface should hide that. mkdirat2 does not exist yet, though patch
    /// sets have been proposed.
    pub fn mkdirat(&self, f: &mut File, path: &Path) -> Result<File> {
        let path = &CString::try_from(path)?.0;
        let mode = self.mode.unwrap_or(0o777);
        // create
        cvt_r(|| unsafe { mkdirat(f.as_raw_fd(), path.as_ptr(), mode) })?;
        // Consider using openat2 on Linux... though that requires direct
        // syscall usage today. https://man7.org/linux/man-pages/man2/openat2.2.html
        let flags = libc::O_CLOEXEC | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY;

        // and open to return it
        let fd = cvt_r(|| unsafe { openat64(f.as_raw_fd(), path.as_ptr(), flags, mode as c_int) })?;
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

pub trait OpenOptionsExt {
    /*!
    Set mode bits for new inode creation.

    This is masked out by umask as well.

    ```no_run
    use std::{fs, os::unix::fs::OpenOptionsExt as StdOpenOptionsExt};

    use fs_at::OpenOptions;
    use fs_at::os::unix::OpenOptionsExt;
    use libc;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW);
    let mut parent_dir = options.open(".").unwrap();
    let mut options = OpenOptions::default();
    options.mode(0o700); // Only permit the euid to access the directory.
    let dir_file = options.mkdirat(&mut parent_dir, "foo");
    ```
    */
    fn mode(&mut self, mode: mode_t) -> &mut Self;
}

impl OpenOptionsExt for OpenOptions {
    fn mode(&mut self, mode: mode_t) -> &mut Self {
        self._impl.mode = Some(mode);
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{rename, File},
        io::Result,
        os::unix::prelude::MetadataExt,
    };

    use tempfile::TempDir;

    use crate::{os::unix::OpenOptionsExt, testsupport::open_dir, OpenOptions};

    #[test]
    fn mkdirat_mode() -> Result<()> {
        let tmp = TempDir::new()?;
        let parent = tmp.path().join("parent");
        let renamed_parent = tmp.path().join("renamed-parent");
        std::fs::create_dir(&parent)?;
        let mut parent_file = open_dir(&parent)?;
        rename(parent, &renamed_parent)?;
        let mut create_opt = OpenOptions::default();
        create_opt.mode(0o700);
        let child: File = create_opt.mkdirat(&mut parent_file, "child")?;
        let expected = renamed_parent.join("child");
        let metadata = expected.symlink_metadata()?;
        assert!(metadata.is_dir());
        assert_eq!(child.metadata()?.mode() & 0o777, 0o700);
        Ok(())
    }
}
