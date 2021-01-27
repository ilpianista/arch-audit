use std::fmt;

use serde::Deserialize;
use strum_macros::{EnumString, EnumVariantNames, ToString};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Deserialize)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Unknown
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Severity::Low => "Low risk",
            Severity::Medium => "Medium risk",
            Severity::High => "High risk",
            Severity::Critical => "Critical risk",
            Severity::Unknown => "Unknown risk",
        })
    }
}

impl Severity {
    pub fn to_color(self) -> term::color::Color {
        match self {
            Severity::Low => term::color::YELLOW,
            Severity::Medium => term::color::BRIGHT_YELLOW,
            Severity::High => term::color::RED,
            Severity::Critical => term::color::BRIGHT_RED,
            _ => term::color::WHITE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Deserialize)]
pub enum Status {
    Unknown,
    #[serde(rename = "Not affected")]
    NotAffected,
    Vulnerable,
    Fixed,
    Testing,
}

impl Default for Status {
    fn default() -> Self {
        Status::Unknown
    }
}

#[derive(Debug, ToString, EnumString, EnumVariantNames)]
#[strum(serialize_all = "snake_case")]
pub enum Color {
    Always,
    Auto,
    Never,
}

impl Default for Color {
    fn default() -> Self {
        Color::Auto
    }
}
