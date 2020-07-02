use crate::enums::{Severity, Status};
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct AVG {
    pub issues: Vec<String>,
    pub fixed: Option<String>,
    pub severity: Severity,
    pub status: Status,
    pub required_by: Vec<String>,
    pub avg_types: HashSet<String>,
}

impl Default for AVG {
    fn default() -> AVG {
        AVG {
            issues: vec![],
            fixed: None,
            severity: Severity::Unknown,
            status: Status::Unknown,
            required_by: vec![],
            avg_types: HashSet::default(),
        }
    }
}
