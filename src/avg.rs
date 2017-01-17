use enums;

#[derive(Clone, Debug)]
pub struct AVG {
    pub issues: Vec<String>,
    pub fixed: Option<String>,
    pub severity: enums::Severity,
    pub status: enums::Status,
}

impl Default for AVG {
    fn default() -> AVG {
        AVG {
            issues: vec![],
            fixed: None,
            severity: enums::Severity::Unknown,
            status: enums::Status::Unknown,
        }
    }
}
