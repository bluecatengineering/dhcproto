#![warn(
    missing_debug_implementations,
    // missing_docs,
    missing_copy_implementations,
    rust_2018_idioms,
    unreachable_pub,
    non_snake_case,
    non_upper_case_globals
)]
#![deny(broken_intra_doc_links)]
#![allow(clippy::cognitive_complexity)]

pub mod decoder;
pub mod encoder;
pub mod error;
pub mod msg;
pub mod v6;
