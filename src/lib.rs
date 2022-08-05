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

#[cfg(windows)]
mod win;

#[cfg(windows)]
use win::OpenOptionsImpl;

#[cfg(unix)]
mod unix;

#[cfg(unix)]
use unix::OpenOptionsImpl;

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

/// Controls the way writes to an opened file are performed. Write modes do not
/// affect how the file is opened - creating the file or truncating it require
/// separate options.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, PartialOrd)]
pub enum OpenOptionsWriteMode {
    /// No writing permitted. Allows opening files where the process lacks write permissions, and attempts to write will fail.
    #[default]
    None,
    /// Writes permitted. The file location pointer tracked by the OS determines
    /// where writes in the file will take place.
    Write,
    /// Writes permitted. The OS will place each write at the current end of the
    /// file. These may still change the file location pointer, so if reads are
    /// being used as well, be sure to seek to the desired location before
    /// reading. One way to do this is to use seek to save the file location
    /// pointer (`seek(SeekFrom::Current(0))`) and then apply the result before
    /// the next read.
    ///
    /// Most OSes and filesystems make these writes atomically, such that
    /// different threads or even processes can collaborate safely on a single
    /// file, as long as each write call provides a full unit of data (e.g. a
    /// line, or a binary struct etc). This can be done by building up the data
    /// to write, or using a buffered writer that is large enough and calling
    /// flush after each unit is complete.
    ///
    /// In particular NFS on Linux is documented as not providing atomic appends.
    ///
    /// ```no_compile
    /// use std::fs::OpenOptions;
    ///
    /// let file = OpenOptions::new().write(OpenOptionsWriteMode::Append).open_at(&mut parent, "foo.txt");
    /// ```
    Append,
}

impl OpenOptions {
    /// Sets the option for read access.
    ///
    /// This option, when true, will indicate that the file should be read-able if opened.
    ///
    /// ```no_compile
    /// use fs_at::OpenOptions;
    ///
    /// let file = OpenOptions::default().read(true).open_at(&mut parent, "foo");
    /// ```
    pub fn read(&mut self, read: bool) -> &mut Self {
        self._impl.read(read);
        self
    }

    /// Sets the option for write access.
    ///
    /// See [`OpenOptionsWriteMode`] for the details of each mode.
    ///
    /// This option on its own is not enough to create a new file.
    ///
    /// ```no_compile
    /// use fs_at::OpenOptions;
    ///
    /// let file = OpenOptions::default().write(OpenOptionsWriteMode::Write).open_at(&mut parent, "foo.txt");
    /// ```
    pub fn write(&mut self, write: OpenOptionsWriteMode) -> &mut Self {
        self._impl.write(write);
        self
    }

    /// Sets the option for truncating a previous file.
    ///
    /// If a file is successfully opened with this option set it will truncate the file to 0 length if it already exists.
    ///
    /// The file must be opened with write access for truncate to work.
    ///
    /// Behaviour of truncate on directories and symlink files is undefined.
    ///
    /// ```no_compile
    /// use std::fs::OpenOptions;
    ///
    /// let file = OpenOptions::new().write(OpenOptionsWriteMode::Append).truncate(true).open_at(&mut parent, "foo.txt");
    /// ```
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self._impl.truncate(truncate);
        self
    }

    /// Set the option to create a new file when missing, while still opening
    /// existing files. Unlike the Rust stdlib, an options with write set to
    /// [`OpenOptionsWriteMode::None`] can still be used to create a new file.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self._impl.create(create);
        self
    }

    /// Set the option to create a new file, rejecting existing entries at the
    /// pathname, whether links or directories.
    ///
    /// This is performed by the OS as an atomic operation, providing safety
    /// against TOCTOU conditions. Whether this will occur as an atomic
    /// operation depends on the OS and filesystem in use. In particular NFS
    /// versions below 3 do not support the needed operations for atomicity.
    ///
    /// Unlike the Rust stdlib, an options with write set to
    /// [`OpenOptionsWriteMode::None`] can still be used to create a new file.
    ///
    /// ```no_compile
    /// use fs_at::OpenOptions;
    ///
    /// let file = OpenOptions::default().write(OpenOptionsWriteMode::Write)
    ///                              .create_new(true)
    ///                              .open_at(&mut parent, "foo.txt");
    /// let dir = OpenOptions::default()
    ///                              .create_new(true)
    ///                              .mkdir_at(&mut parent, "foo.txt");
    /// ```
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self._impl.create_new(create_new);
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
    #[cfg(unix)]
    pub use crate::unix::exports as unix;
    #[cfg(windows)]
    pub use crate::win::exports as windows;
}

#[cfg(test)]
pub mod testsupport;

#[cfg(test)]
mod tests {
    use std::{
        fs::{rename, File},
        io::{Error, ErrorKind, Result, Seek, SeekFrom, Write},
        path::PathBuf,
    };

    use tempfile::TempDir;

    use crate::{testsupport::open_dir, OpenOptions, OpenOptionsWriteMode};

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
        #[allow(unused)]
        OpenDir,
    }

    #[derive(Default, Debug, Clone)]
    struct Test {
        pub create: bool,
        pub create_new: bool,
        pub read: bool,
        pub write: OpenOptionsWriteMode,
        pub truncate: bool,
        pub op: Op,
    }

    impl Test {
        fn create(mut self, create: bool) -> Self {
            self.create = create;
            self
        }

        fn create_new(mut self, create_new: bool) -> Self {
            self.create_new = create_new;
            self
        }

        fn read(mut self, read: bool) -> Self {
            self.read = read;
            self
        }

        fn write(mut self, write: OpenOptionsWriteMode) -> Self {
            self.write = write;
            self
        }

        fn truncate(mut self, truncate: bool) -> Self {
            self.truncate = truncate;
            self
        }

        fn op(mut self, op: Op) -> Self {
            self.op = op;
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
                Op::OpenFile => {
                    let mut first_file = OpenOptions::default()
                        .create(true)
                        .write(OpenOptionsWriteMode::Write)
                        .open_at(&mut parent_file, "child")?;
                    assert_eq!(16, first_file.write(b"existing content")?);
                    first_file.flush()?;
                }
            }
        }
        if test.create {
            options.create(true);
        }
        if test.create_new {
            options.create_new(true);
        }
        if test.read {
            options.read(true);
        }
        options.write(test.write);
        if test.truncate {
            options.truncate(true);
        }

        let res = match test.op {
            Op::MkDir => options.mkdir_at(&mut parent_file, "child"),
            Op::OpenDir => unimplemented!(),
            Op::OpenFile => options.open_at(&mut parent_file, "child"),
        };
        let mut child = match (res, err) {
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
                // If the file was truncated, it will be 0-length.
                // If the file is new it will be 0-length.
                let initial_length = metadata.len();
                if test.truncate || !create_in_advance {
                    assert_eq!(initial_length, 0);
                } else {
                    assert_eq!(initial_length, 16);
                }
                if test.write != OpenOptionsWriteMode::None {
                    child.seek(SeekFrom::Start(10))?;
                    assert_eq!(10, child.write(b"some data\n")?);
                    if test.write == OpenOptionsWriteMode::Write {
                        assert_eq!(expected.symlink_metadata()?.len(), 20);
                    } else {
                        // The write location is ignored in append mode
                        assert_eq!(expected.symlink_metadata()?.len(), initial_length + 10);
                    }
                }
                //
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
        if test.create_new {
            // run three tests: one that creates the path, and one that expects
            // an error operating on the existing path, and one that expects an
            // error likewise operating on an existing symlink
            _check_behaviour(test.clone(), false, None)?;
            let err = Error::from(ErrorKind::AlreadyExists);
            _check_behaviour(test, true, Some(&err))
        } else if test.create || test.truncate {
            // run two tests: one that creates the path, and once that opens
            // the existing path
            _check_behaviour(test.clone(), true, None)?;
            _check_behaviour(test, false, None)
        } else {
            // without create/create_new/truncate, openat is only useful on
            // existing files.
            if test.op != Op::MkDir {
                return Ok(());
            }
            // run two tests: one that creates the path where it didn't exist
            // and one that precreates the file and expects an error
            _check_behaviour(test.clone(), false, None)?;
            let err = Error::from(ErrorKind::AlreadyExists);
            _check_behaviour(test, true, Some(&err))
        }
    }

    #[test]
    fn all_mkdir() -> Result<()> {
        for create in &[false, true] {
            for create_new in &[false, true] {
                for read in &[false, true] {
                    for write in &[
                        OpenOptionsWriteMode::None,
                        OpenOptionsWriteMode::Write,
                        OpenOptionsWriteMode::Append,
                    ] {
                        check_behaviour(
                            Test::default()
                                .create(*create)
                                .create_new(*create_new)
                                .read(*read)
                                .write(*write)
                                .op(Op::MkDir),
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn all_open_file() -> Result<()> {
        for create in &[false, true] {
            for create_new in &[false, true] {
                for read in &[false, true] {
                    for write in &[
                        OpenOptionsWriteMode::None,
                        OpenOptionsWriteMode::Write,
                        OpenOptionsWriteMode::Append,
                    ] {
                        for truncate in &[false, true] {
                            // Filter for open: without one of read/write/append all
                            // calls will fail
                            if !read && *write == OpenOptionsWriteMode::None {
                                continue;
                            }
                            check_behaviour(
                                Test::default()
                                    .create(*create)
                                    .create_new(*create_new)
                                    .read(*read)
                                    .write(*write)
                                    .truncate(*truncate)
                                    .op(Op::OpenFile),
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
