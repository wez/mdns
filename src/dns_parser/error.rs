use std::str::Utf8Error;
use thiserror::Error;

/// Error parsing DNS packet
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid compression pointer not pointing backwards
    /// when parsing label
    #[error(
        "invalid compression pointer not pointing backwards \
                         when parsing label"
    )]
    BadPointer,
    /// Packet is smaller than header size
    #[error("packet is smaller than header size")]
    HeaderTooShort,
    /// Packet ihas incomplete data
    #[error("packet is has incomplete data")]
    UnexpectedEOF,
    /// Wrong (too short or too long) size of RDATA
    #[error("wrong (too short or too long) size of RDATA")]
    WrongRdataLength,
    /// Packet has non-zero reserved bits
    #[error("packet has non-zero reserved bits")]
    ReservedBitsAreNonZero,
    /// Label in domain name has unknown label format
    #[error("label in domain name has unknown label format")]
    UnknownLabelFormat,
    /// Query type code is invalid
    #[error("query type {} is invalid", .0)]
    InvalidQueryType(u16),
    /// Query class code is invalid
    #[error("query class {} is invalid", .0)]
    InvalidQueryClass(u16),
    /// Type code is invalid
    #[error("type {} is invalid", .0)]
    InvalidType(u16),
    /// Class code is invalid
    #[error("class {} is invalid", .0)]
    InvalidClass(u16),
    /// Invalid characters encountered while reading label
    #[error("invalid characters encountered while reading label")]
    LabelIsNotUtf8,
    /// Invalid characters encountered while reading TXT
    #[error("invalid characters encountered while reading TXT: {:?}", .0)]
    TxtDataIsNotUTF8(Utf8Error),
    /// Parser is in the wrong state
    #[error("parser is in the wrong state")]
    WrongState,
    /// Additional OPT record found
    #[error("additional OPT record found")]
    AdditionalOPT,
}
