use std::{
    ffi::{CString, OsStr, OsString},
    fs::File,
    io::Result,
    marker::PhantomData,
    os::unix::prelude::{AsRawFd, FromRawFd, OsStrExt},
    path::Path,
    ptr,
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

use crate::{OpenOptions, OpenOptionsWriteMode};

pub mod exports {
    pub use super::OpenOptionsExt;
    #[doc(no_inline)]
    pub use libc::mode_t;
}

trait PathFFI {
    fn as_cstring(&self) -> Result<CString>;
}

impl PathFFI for Path {
    fn as_cstring(&self) -> Result<CString> {
        std::ffi::CString::new(self.as_os_str().as_bytes())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

#[derive(Debug, Default)]
pub(crate) struct OpenOptionsImpl {
    read: bool,
    write: OpenOptionsWriteMode,
    truncate: bool,
    create: bool,
    create_new: bool,
    mode: Option<mode_t>,
}

impl OpenOptionsImpl {
    pub fn read(&mut self, read: bool) {
        self.read = read;
    }

    pub fn write(&mut self, write: OpenOptionsWriteMode) {
        self.write = write;
    }

    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }

    pub fn create(&mut self, create: bool) {
        self.create = create;
    }

    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
    }

    fn get_flags(&self) -> Result<c_int> {
        let data_flags = match (self.read, self.write) {
            (false, OpenOptionsWriteMode::Write) => Ok(libc::O_WRONLY),
            (false, OpenOptionsWriteMode::Append) => Ok(libc::O_WRONLY | libc::O_APPEND),
            (false, OpenOptionsWriteMode::None) => {
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
            (true, OpenOptionsWriteMode::None) => Ok(libc::O_RDONLY),
            (true, OpenOptionsWriteMode::Write) => Ok(libc::O_RDWR),
            (true, OpenOptionsWriteMode::Append) => Ok(libc::O_RDWR | libc::O_APPEND),
        }?;

        let create_flags = if self.create_new {
            libc::O_EXCL | libc::O_CREAT
        } else if self.truncate {
            libc::O_CREAT | libc::O_TRUNC
        } else if self.create {
            libc::O_CREAT
        } else {
            0
        };

        // Some / all of these need to become OpenOptions controls.
        let common_flags = libc::O_CLOEXEC | libc::O_NOCTTY;
        // We should add an extension to suppport libc::O_PATH as NtCreateFile
        // has a matching capability.
        // Similarly O_TMPFILE
        Ok(data_flags | create_flags | common_flags)
    }

    pub fn open_at(&self, d: &mut File, path: &Path) -> Result<File> {
        let path = path.as_cstring()?;
        let mode = self.mode.unwrap_or(0o777);
        let flags = self.get_flags()?;

        // TODO
        // Consider using openat2 on Linux... though that requires direct
        // syscall usage today. https://man7.org/linux/man-pages/man2/openat2.2.html
        let fd = cvt_r(|| unsafe { openat64(d.as_raw_fd(), path.as_ptr(), flags, mode as c_int) })?;

        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// One note: as the widespread unix interfaces don't offer atomic
    /// create-and-open, there is a race condition here (which is bad as this
    /// crate exists to target race conditions). Possibly addressable by a
    /// create-random + atomic move into place, but it isn't clear that this
    /// interface should hide that. mkdirat2 does not exist yet, though patch
    /// sets have been proposed. The second wart is that a non-O_EXCL mode
    /// doesn't exist: mkdir_at() fails if the target exists and is a dir
    /// already.
    pub fn mkdir_at(&self, d: &mut File, path: &Path) -> Result<File> {
        let path = path.as_cstring()?;
        let mode = self.mode.unwrap_or(0o777);
        // create
        match cvt_r(|| unsafe { mkdirat(d.as_raw_fd(), path.as_ptr(), mode) }) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // IFF exclusive wasn't requested (currently the default), then
                // proceed to open-as-dir and return existing dir.
                if self.create && !self.create_new {
                    Ok(())
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
            Ok(_) => Ok(()),
        }?;

        // Consider using openat2 on Linux... though that requires direct
        // syscall usage today. https://man7.org/linux/man-pages/man2/openat2.2.html
        let flags = libc::O_CLOEXEC | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY;

        // and open to return it
        let fd = cvt_r(|| unsafe { openat64(d.as_raw_fd(), path.as_ptr(), flags, mode as c_int) })?;
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
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
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

#[derive(Debug)]
pub(crate) struct ReadDirImpl<'a> {
    // Since we clone the FD, the original FD is now separate. In theory.
    // However for Windows we use the File directly, thus here we need to
    // pretend.
    _phantom: PhantomData<&'a File>,
    // Set to None after we closedir it. Perhaps we should we impl Send and Sync
    // because the data referenced is owned by libc ?
    dir: Option<ptr::NonNull<libc::DIR>>,
}

impl<'a> ReadDirImpl<'a> {
    pub fn new(dir_file: &'a mut File) -> Result<Self> {
        // closedir closes the FD; make a new one that we can close when done with.
        let new_fd =
            cvt_r(|| unsafe { libc::fcntl(dir_file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
        let mut dir = Some(
            ptr::NonNull::new(unsafe { libc::fdopendir(new_fd) }).ok_or_else(|| {
                let _droppable = unsafe { File::from_raw_fd(new_fd) };
                std::io::Error::last_os_error()
            })?,
        );

        // If dir_file has had operations on it - such as open_at - its pointer
        // might not be at the start of the dir, and fdopendir is documented
        // (e.g. BSD man pages) to not rewind the fd - and our cloned fd
        // inherits the pointer.
        if let Some(d) = dir.as_mut() {
            unsafe { libc::rewinddir(d.as_mut()) };
        }

        Ok(ReadDirImpl {
            _phantom: PhantomData,
            dir,
        })
    }

    fn close_dir(&mut self) -> Result<()> {
        if let Some(ref mut dir) = self.dir {
            let result = unsafe { libc::closedir(dir.as_mut()) };
            // call made, clear state
            self.dir = None;
            cvt_r(|| result)?;
        }
        Ok(())
    }
}

impl Drop for ReadDirImpl<'_> {
    fn drop(&mut self) {
        // like the stdlib, we eat errors occuring during drop, as there is no
        // way to get error handling.
        let _ = self.close_dir();
    }
}

impl Iterator for ReadDirImpl<'_> {
    type Item = Result<DirEntryImpl>;

    fn next(&mut self) -> Option<Self::Item> {
        let dir = unsafe { self.dir?.as_mut() };
        // the readdir result is only guaranteed valid within the same thread
        // and until other calls are made on the same dir stream. Thus we
        // perform the required work inside next, allowing the next call to
        // readdir to be managed by the single mutable borrower rule in Rust.
        // readdir requires errno set to zero.
        nix::Error::clear();
        ptr::NonNull::new(unsafe { libc::readdir(dir) })
            .map(|e| {
                Ok(DirEntryImpl {
                    name: unsafe {
                        // Step one: C pointer to CStr - referenced data, length not known.
                        let c_str = std::ffi::CStr::from_ptr(e.as_ref().d_name.as_ptr());
                        // Step two: OsStr: referenced data, length calcu;ated
                        let os_str = OsStr::from_bytes(c_str.to_bytes());
                        // Step three: owned copy
                        os_str.to_os_string()
                    },
                })
            })
            .or_else(|| {
                // NULL result, an error IFF errno has been set.
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(0) {
                    None
                } else {
                    Some(Err(err))
                }
            })
    }
}

#[derive(Debug)]
pub(crate) struct DirEntryImpl {
    name: OsString,
}

impl DirEntryImpl {
    pub fn name(&self) -> &OsStr {
        &self.name
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
        let child: File = create_opt.mkdir_at(&mut parent_file, "child")?;
        let expected = renamed_parent.join("child");
        let metadata = expected.symlink_metadata()?;
        assert!(metadata.is_dir());
        assert_eq!(child.metadata()?.mode() & 0o777, 0o700);
        Ok(())
    }
}
