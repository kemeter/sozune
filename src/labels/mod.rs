//! Provider-agnostic label parsing and validation.
//!
//! Each provider (docker, file, nomad, k8s) produces `Candidate` values from its
//! native source. The shared parser turns a `Candidate` into a `ParseResult`
//! containing the entrypoints sozune would create plus a list of `Diagnostic`
//! describing every silent fallback or skip the parser had to make.
//!
//! Both the runtime and `sozune validate` consume the same parser, so what
//! validate reports cannot drift from what production actually does.

pub mod candidate;
pub mod catalog;
pub mod diagnostic;
pub mod fields;
pub mod network;
pub mod parser;
pub mod source;

pub use candidate::{Candidate, NetworkInfo};
pub use diagnostic::{Diagnostic, DiagnosticCode, ParseResult, Severity};
pub use parser::parse;
pub use source::LabelSource;
