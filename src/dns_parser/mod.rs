//! The network-agnostic DNS parser library
//!
//! [Documentation](https://docs.rs/dns-parser) |
//! [Github](https://github.com/tailhook/dns-parser) |
//! [Crate](https://crates.io/crates/dns-parser)
//!
//! Use [`Builder`] to create a new outgoing packet.
//!
//! Use [`Packet::parse`] to parse a packet into a data structure.
//!
//! [`Builder`]: struct.Builder.html
//! [`Packet::parse`]: struct.Packet.html#method.parse
//!
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

mod builder;
mod enums;
mod error;
mod header;
mod name;
mod parser;
mod structs;

pub mod rdata;

pub use crate::dns_parser::builder::Builder;
pub use crate::dns_parser::enums::{Class, Opcode, QueryClass, QueryType, ResponseCode, Type};
pub use crate::dns_parser::error::Error;
pub use crate::dns_parser::header::Header;
pub use crate::dns_parser::name::Name;
pub use crate::dns_parser::rdata::RData;
pub use crate::dns_parser::structs::{Packet, Question, ResourceRecord};
