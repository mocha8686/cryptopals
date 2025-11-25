#![allow(clippy::missing_errors_doc, reason = "ignore docs for now")]

pub mod data;
pub mod error;

pub use data::Data;
pub use error::{Error, Result};
