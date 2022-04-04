# At calls for Rust

The Rust standard library does not (yet) offer at filesystem calls as a core
feature. For instance `mkdirat`. These calls are essential for writing race-free
filesystem code, since otherwise the state of the filesystem path that
operations are executed against can change silently, leading to TOC-TOU race
conditions. For Unix these calls are readily available in the libc crate, but
for Windows some more plumbing is needed, which this crate provides.

## Usage

See the crate docs.

## Contributing

PR's as normal on Github.

## Code of conduct

Please note that this project is released with a Contributor Code of Conduct. By
participating in this project you agree to abide by its terms.