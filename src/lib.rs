//! Extension for operations that manipulate the file system relative to an open
//! directory, rather than the global namespace.
//!
//! NB: If a missing capability or platform is found, I will happily add /
//! accept patches : features are being added as needed, rather than
//! speculatively.
//!
//! The Rust standard library does not (yet) offer at filesystem calls as a core
//! feature. For instance `mkdirat`. These calls are essential for writing
//! race-free filesystem code, since otherwise the state of the filesystem path
//! that operations are executed against can change silently, leading to TOC-TOU
//! race conditions. For Unix these calls are readily available in the libc
//! crate, but for Windows some more plumbing is needed. This crate provides a
//! unified Rust-y interface to these calls.

use std::{
    fs::File,
    io::{Error, ErrorKind, Result},
    path::Path,
};

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        mod win;

        use win::OpenOptionsImpl;
    } else {
        mod unix;

        use unix::OpenOptionsImpl;
    }
}

/// Similar to [`std::fs::OpenOptions`], this struct is used to parameterise the
/// various at functions, which are then called on the struct itself. Typical
/// use is to create a struct via [`Default::default`] or
/// [`OpenOptions::default()`], and then customise it as desired (e.g. setting
/// security descriptors on windows, or mode on unix) using an appropriate
/// platform specific trait, finishing up with the desired manipulation e.g.
/// `mkdirat`.
#[derive(Default, Debug)]
pub struct OpenOptions {
    _impl: OpenOptionsImpl,
}

impl OpenOptions {
    /// Set the option to create a new file when missing, while still opening
    /// existing files.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self._impl.create(create);
        self
    }

    /// Create a directory relative to an open directory. Errors if a rooted
    /// path is provided.
    ///
    /// Returns a [`File`] opened on the created directory.
    ///
    /// On Windows this is done without resolving names a second time, in a
    /// single syscall.
    ///
    /// On Unix, an additional openat syscall is performed to open the created
    /// directory. This limitation may be lifted in future if the mooted
    /// mkdirat2 call gets created.. The mode of the new directory defaults to
    /// 0o777.
    pub fn mkdir_at<P: AsRef<Path>>(&self, d: &mut File, p: P) -> Result<File> {
        self._impl
            .mkdir_at(d, OpenOptions::ensure_root(p.as_ref())?)
    }

    /// Opens a file at the path p relative to the directory d.
    ///
    /// This will honour the options set for creation/append etc, but will only
    /// operate relative to d. To open a file with an absolute path, use the
    /// stdlib fs::OpenOptions.
    pub fn open_at<P: AsRef<Path>>(&self, d: &mut File, p: P) -> Result<File> {
        self._impl.open_at(d, OpenOptions::ensure_root(p.as_ref())?)
    }

    fn ensure_root(p: &Path) -> Result<&Path> {
        if p.has_root() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Rooted file path {p:?}"),
            ));
        }
        Ok(p)
    }
}

pub mod os {
    cfg_if::cfg_if! {
        if #[cfg(windows)] {
            pub use crate::win::exports as windows;
        } else {
            pub use crate::unix::exports as unix;
        }
    }
}

#[cfg(test)]
pub mod testsupport;

#[cfg(test)]
mod tests {
    use std::{
        fs::{rename, File},
        io::Result,
        path::PathBuf,
    };

    use tempfile::TempDir;

    use crate::{testsupport::open_dir, OpenOptions};

    /// Create a directory parent, open it, then rename it to renamed-parent and
    /// create another directory in its place. returns the file handle and the
    /// final path.
    fn setup() -> Result<(TempDir, File, PathBuf)> {
        let tmp = TempDir::new()?;
        let parent = tmp.path().join("parent");
        let renamed_parent = tmp.path().join("renamed-parent");
        std::fs::create_dir(&parent)?;
        let parent_file = open_dir(&parent)?;
        rename(parent, &renamed_parent)?;
        Ok((tmp, parent_file, renamed_parent))
    }

    #[test]
    fn mkdirat_simple() -> Result<()> {
        // mk a new dir
        let (_tmp, mut parent_file, renamed_parent) = setup()?;
        let _child: File = OpenOptions::default().mkdir_at(&mut parent_file, "child")?;
        let expected = renamed_parent.join("child");
        let metadata = expected.symlink_metadata()?;
        assert!(metadata.is_dir());
        Ok(())
    }

    #[test]
    fn mkdirat_permit_existing() -> Result<()> {
        let (_tmp, mut parent_file, renamed_parent) = setup()?;
        OpenOptions::default().mkdir_at(&mut parent_file, "child")?;
        let _child: File = OpenOptions::default()
            .create(true)
            .mkdir_at(&mut parent_file, "child")?;
        let expected = renamed_parent.join("child");
        let metadata = expected.symlink_metadata()?;
        assert!(metadata.is_dir());
        Ok(())
    }

    #[test]
    fn mkdirat_error_existing() -> Result<()> {
        let (_tmp, mut parent_file, _) = setup()?;
        OpenOptions::default().mkdir_at(&mut parent_file, "child")?;
        OpenOptions::default()
            .mkdir_at(&mut parent_file, "child")
            .unwrap_err();
        Ok(())
    }

    #[test]
    fn openat_create_new() -> Result<()> {
        let (_tmp, mut parent_file, renamed_parent) = setup()?;
        let _child: File = OpenOptions::default()
            .create(true)
            .open_at(&mut parent_file, "child")?;
        let expected = renamed_parent.join("child");
        let metadata = expected.symlink_metadata()?;
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), 0);
        Ok(())
    }
}
