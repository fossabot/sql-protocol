#![allow(dead_code)]
#![allow(clippy::needless_return)]
#![allow(clippy::redundant_static_lifetimes)]
#![feature(box_syntax)]
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate lazy_static;

mod constants;
mod errors;
mod proto;
mod sql_type;

pub use crate::proto::{Handler, Listener};
pub use crate::sql_type::SqlResult;
