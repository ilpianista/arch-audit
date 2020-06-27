use crate::enums::{Severity, Status};

#[derive(Clone, Debug)]
pub struct AVG {
    pub issues: Vec<String>,
    pub fixed: Option<String>,
    pub severity: Severity,
    pub status: Status,
    pub required_by: Vec<String>,
    pub avg_type: String,
}

impl Default for AVG {
    fn default() -> AVG {
        AVG {
            issues: vec![],
            fixed: None,
            severity: Severity::Unknown,
            status: Status::Unknown,
            required_by: vec![],
            avg_type: String::default(),
        }
    }
}
