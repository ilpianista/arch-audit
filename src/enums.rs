use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl FromStr for Severity {
    type Err = ();

    fn from_str(s: &str) -> Result<Severity, ()> {
        match s {
            "Low" => Ok(Severity::Low),
            "Medium" => Ok(Severity::Medium),
            "High" => Ok(Severity::High),
            "Critical" => Ok(Severity::Critical),
            _ => Ok(Severity::Unknown),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Unknown,
    Vulnerable,
    Testing,
    Fixed,
    NotAffected,
}

impl FromStr for Status {
    type Err = ();

    fn from_str(s: &str) -> Result<Status, ()> {
        match s {
            "Vulnerable" => Ok(Status::Vulnerable),
            "Testing" => Ok(Status::Testing),
            "Fixed" => Ok(Status::Fixed),
            "Not affected" => Ok(Status::NotAffected),
            _ => Ok(Status::Unknown),
        }
    }
}
