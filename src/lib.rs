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
    /// Sets the option for read access.
    ///
    /// This option, when true, will indicate that the file should be read-able if opened.
    ///
    /// ```no_compile
    /// use fs_at::OpenOptions;
    ///
    /// let file = OpenOptions::default().read(true).open_at(parent, "foo");
    /// ```
    pub fn read(&mut self, read: bool) -> &mut Self {
        self._impl.read(read);
        self
    }

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
        io::{Error, ErrorKind, Result},
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

    #[derive(Default, Debug, Clone, PartialEq, PartialOrd)]
    enum Op {
        // Perform a mkdirat call
        #[default]
        MkDir,
        // perform an open call on a file
        OpenFile,
        // perform an open call on a dir ? [should this be extension only?]
        OpenDir,
    }

    #[derive(Default, Debug, Clone)]
    struct Test<'a> {
        pub create: bool,
        pub read: bool,
        pub op: Op,
        pub err: Option<&'a Error>,
    }

    impl<'a> Test<'a> {
        fn create(mut self, create: bool) -> Self {
            self.create = create;
            self
        }

        fn read(mut self, read: bool) -> Self {
            self.read = read;
            self
        }

        fn op(mut self, op: Op) -> Self {
            self.op = op;
            self
        }

        fn err(mut self, err: Option<&'a Error>) -> Self {
            self.err = err;
            self
        }
    }

    fn _check_behaviour(test: Test, create_in_advance: bool, err: Option<&Error>) -> Result<()> {
        eprintln!(
            "testing op: {:?} create_in_advance: {}, err: {:?}",
            test, create_in_advance, err
        );
        let (_tmp, mut parent_file, renamed_parent) = setup()?;
        let mut options = OpenOptions::default();

        if create_in_advance {
            match test.op {
                Op::MkDir => {
                    options.mkdir_at(&mut parent_file, "child")?;
                }
                Op::OpenDir => (),
                Op::OpenFile => (),
            }
        }
        if test.create {
            options.create(true);
        }
        if test.read {
            options.read(true);
        }

        let res = match test.op {
            Op::MkDir => options.mkdir_at(&mut parent_file, "child"),
            Op::OpenDir => unimplemented!(),
            Op::OpenFile => options.open_at(&mut parent_file, "child"),
        };
        let _child = match (res, err) {
            (Ok(child), None) => child,
            (Ok(_), Some(e)) => panic!("unexpected success {:?}", e),
            (Err(e), None) => panic!("unexpected error {:?}", e),
            (Err(e), Some(expected_e)) => {
                assert_eq!(e.kind(), expected_e.kind(), "{:?} != {:?}", e, expected_e);
                return Ok(());
            }
        };
        let expected = renamed_parent.join("child");
        let metadata = expected.symlink_metadata()?;
        match test.op {
            Op::MkDir => assert!(metadata.is_dir()),
            Op::OpenDir => (),
            Op::OpenFile => {
                assert!(metadata.is_file());
                assert_eq!(metadata.len(), 0);
            }
        }
        Ok(())
    }

    // basic property based framework. Performs a specific combination of
    // options with a file-or-dir opening call, and verifies the resulting
    // object can be used as expected. Note that this cannot be used to create
    // actual races - but the library depends on the OS behaviour for race
    // safety: what we are checking for here is that we're passing the right
    // semantics down for when races do occur (e.g. O_EXCL is supplied when
    // requested...)
    fn check_behaviour(test: Test) -> Result<()> {
        if test.create {
            // run two tests: one that creates the path, and once that opens
            // the existing path
            _check_behaviour(test.clone(), true, None)?;
            _check_behaviour(test.clone(), false, None)
        } else {
            // without create, openat is only useful on existing files.
            if test.op != Op::MkDir {
                return Ok(());
            }
            // choose one of two tests: one that creates the path where it didn't exist
            // and one that precreates the file and expects an error
            if test.err.is_none() {
                _check_behaviour(test.clone(), false, None)
            } else {
                _check_behaviour(test.clone(), true, test.err)
            }
        }
    }

    #[test]
    fn all_mkdir() -> Result<()> {
        let err = Error::from(ErrorKind::AlreadyExists);
        for err_ref in vec![None, Some(&err)].into_iter() {
            for create in vec![false, true] {
                for read in vec![false, true] {
                    check_behaviour(
                        Test::default()
                            .err(err_ref)
                            .create(create)
                            .read(read)
                            .op(Op::MkDir),
                    )?;
                }
            }
        }
        Ok(())
    }

    #[test]
    fn all_open_file() -> Result<()> {
        let err = Error::from(ErrorKind::AlreadyExists);
        for err_ref in vec![None, Some(&err)].into_iter() {
            for create in vec![false, true] {
                for read in vec![false, true] {
                    // Filter for open: without one of read/write/append all
                    // calls will fail
                    if !read {
                        continue;
                    }
                    check_behaviour(
                        Test::default()
                            .err(err_ref)
                            .create(create)
                            .read(read)
                            .op(Op::OpenFile),
                    )?;
                }
            }
        }
        Ok(())
    }
}
