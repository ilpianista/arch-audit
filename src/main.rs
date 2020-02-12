extern crate alpm;
#[macro_use]
extern crate clap;
extern crate curl;
extern crate env_logger;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate serde_json;
extern crate term;

use clap::App;
use curl::easy::Easy;
use itertools::Itertools;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::collections::BTreeMap;
use std::default::Default;
use std::process::exit;
use std::str;

mod avg;
mod enums;

const WEBSITE: &str = "https://security.archlinux.org";
const ROOT_DIR: &str = "/";
const DB_PATH: &str = "/var/lib/pacman/";

struct Options {
    format: Option<String>,
    quiet: u64,
    upgradable_only: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            format: None,
            quiet: 0,
            upgradable_only: false,
        }
    }
}

fn main() {
    env_logger::init();

    let yaml = load_yaml!("cli.yml");
    let args = App::from_yaml(yaml).get_matches();

    let options = Options {
        format: {
            match args.value_of("format") {
                Some(f) => Some(f.to_string()),
                None => None,
            }
        },
        quiet: args.occurrences_of("quiet"),
        upgradable_only: args.is_present("upgradable"),
    };

    let mut avgs = String::new();
    {
        info!("Downloading AVGs...");
        let avgs_url = format!("{}/issues/all.json", WEBSITE);

        let mut easy = Easy::new();
        easy.fail_on_error(true)
            .expect("curl::Easy::fail_on_error failed");
        easy.url(&avgs_url).expect("curl::Easy::url failed");
        let mut transfer = easy.transfer();
        transfer
            .write_function(|data| {
                avgs.push_str(str::from_utf8(data).expect("str conversion failed"));
                Ok(data.len())
            })
            .expect("write_function failed");
        match transfer.perform() {
            Ok(_) => {}
            Err(_) => {
                println!(
                    "Cannot fetch data from {}, please check your network connection!",
                    WEBSITE
                );
                exit(1)
            }
        };
    }

    let pacman = match args.value_of("dbpath") {
        Some(path) => {
            alpm::Alpm::new(ROOT_DIR, path).expect("alpm::Alpm::new with custom dbpath failed")
        }
        None => alpm::Alpm::new(ROOT_DIR, DB_PATH).expect("alpm::Alpm::new failed"),
    };
    let db = pacman.localdb();

    let mut cves: BTreeMap<String, Vec<_>> = BTreeMap::new();
    {
        let json: Value = serde_json::from_str(&avgs).expect("serde_json::from_str failed");

        for avg in json.as_array().expect("Value::as_array failed") {
            let packages = avg["packages"]
                .as_array()
                .expect("Value::as_array failed")
                .iter()
                .map(|s| s.as_str().expect("Value::as_str failed").to_string())
                .collect::<Vec<_>>();

            if !package_is_installed(&db, &packages) {
                continue;
            }

            let info = to_avg(avg);

            if info.status != enums::Status::NotAffected {
                for p in packages {
                    match cves.entry(p) {
                        Occupied(c) => c.into_mut(),
                        Vacant(c) => c.insert(vec![]),
                    }
                    .push(info.clone());
                }
            }
        }
    }

    let mut affected_avgs: BTreeMap<String, Vec<_>> = BTreeMap::new();
    for (pkg, avgs) in cves {
        for avg in &avgs {
            if system_is_affected(&db, &pkg, avg) {
                match affected_avgs.entry(pkg.clone()) {
                    Occupied(c) => c.into_mut(),
                    Vacant(c) => c.insert(vec![]),
                }
                .push(avg.clone());
            }
        }
    }

    let merged = merge_avgs(&affected_avgs);
    print_avgs(&options, &merged);
}

/// Converts a JSON to an `avg::AVG`
fn to_avg(data: &Value) -> avg::AVG {
    let severity = data["severity"]
        .as_str()
        .expect("Value::as_str failed")
        .to_string()
        .parse::<enums::Severity>()
        .expect("parse::<Severity> failed");
    avg::AVG {
        issues: data["issues"]
            .as_array()
            .expect("Value::as_array failed")
            .iter()
            .map(|s| {
                (
                    s.as_str().expect("Value::as_str failed").to_string(),
                    severity,
                )
            })
            .collect(),
        fixed: match data["fixed"].as_str() {
            Some(s) => Some(s.to_string()),
            None => None,
        },
        severity: severity,
        status: data["status"]
            .as_str()
            .expect("Value::as_str failed")
            .to_string()
            .parse::<enums::Status>()
            .expect("parse::<Status> failed"),
    }
}

#[test]
fn test_to_avg() {
    let json: Value = serde_json::from_str(
        "{\"issues\": [\"CVE-1\", \"CVE-2\"], \"fixed\": \"1.0\", \
         \"severity\": \"High\", \"status\": \"Not affected\"}",
    )
    .expect("serde_json::from_str failed");

    let avg1 = to_avg(&json);
    assert_eq!(2, avg1.issues.len());
    assert_eq!(Some("1.0".to_string()), avg1.fixed);
    assert_eq!(enums::Severity::High, avg1.severity);
    assert_eq!(enums::Status::NotAffected, avg1.status);

    let json: Value = serde_json::from_str(
        "{\"issues\": [\"CVE-1\"], \"fixed\": null, \
         \"severity\": \"Low\", \"status\": \"Vulnerable\"}",
    )
    .expect("serde_json::from_str failed");

    let avg2 = to_avg(&json);
    assert_eq!(1, avg2.issues.len());
    assert_eq!(None, avg2.fixed);
    assert_eq!(enums::Severity::Low, avg2.severity);
    assert_eq!(enums::Status::Vulnerable, avg2.status);
}

/// Given a package and an `avg::AVG`, returns true if the system is affected
fn system_is_affected(db: &alpm::Db, pkg: &str, avg: &avg::AVG) -> bool {
    match db.pkg(pkg.clone()) {
        Ok(v) => {
            info!(
                "Found installed version {} for package {}",
                v.version(),
                pkg
            );
            match avg.fixed {
                Some(ref version) => {
                    info!("Comparing with fixed version {}", version);
                    let cmp = alpm::vercmp(v.version().to_string(), version.clone());
                    if let Ordering::Less = cmp {
                        return true;
                    }
                }
                None => return true,
            };
        }
        Err(_) => debug!("Package {} not installed", pkg),
    }

    false
}

#[test]
fn test_system_is_affected() {
    let pacman = alpm::Alpm::new(ROOT_DIR, DB_PATH).expect("Alpm::new failed");
    let db = pacman.localdb();

    let avg1 = avg::AVG {
        issues: vec![
            ("CVE-1".to_string(), enums::Severity::Unknown),
            ("CVE-2".to_string(), enums::Severity::Unknown),
        ],
        fixed: Some("1.0.0".to_string()),
        severity: enums::Severity::Unknown,
        status: enums::Status::Unknown,
    };

    assert_eq!(false, system_is_affected(&db, &"pacman".to_string(), &avg1));

    let avg2 = avg::AVG {
        issues: vec![
            ("CVE-1".to_string(), enums::Severity::Unknown),
            ("CVE-2".to_string(), enums::Severity::Unknown),
        ],
        fixed: Some("7.0.0".to_string()),
        severity: enums::Severity::Unknown,
        status: enums::Status::Unknown,
    };

    assert!(system_is_affected(&db, &"pacman".to_string(), &avg2));
}

/// Given a list of package names, returns true when at least one is installed
fn package_is_installed(db: &alpm::Db, packages: &[String]) -> bool {
    for pkg in packages {
        match db.pkg(pkg.as_str()) {
            Ok(_) => {
                info!("Package {} is installed", pkg);
                return true;
            }
            Err(_) => debug!("Package {} not installed", pkg),
        }
    }
    false
}

#[test]
fn test_package_is_installed() {
    let pacman = alpm::Alpm::new(ROOT_DIR, DB_PATH).expect("Alpm::new failed");
    let db = pacman.localdb();

    let packages = vec!["pacman".to_string(), "pac".to_string()];
    assert!(package_is_installed(&db, &packages));

    let packages = vec!["pac".to_string()];
    assert_eq!(false, package_is_installed(&db, &packages));
}

/// Merge a list of `avg::AVG` into a single `avg::AVG` using major version as version
fn merge_avgs(cves: &BTreeMap<String, Vec<avg::AVG>>) -> BTreeMap<String, avg::AVG> {
    let mut avgs: BTreeMap<String, avg::AVG> = BTreeMap::new();
    for (pkg, list) in cves.iter() {
        let mut avg_issues = vec![];
        let mut avg_fixed: Option<String> = None;
        let mut avg_severity = enums::Severity::Unknown;
        let mut avg_status = enums::Status::Unknown;

        for a in list.iter() {
            avg_issues.append(&mut a.issues.clone());

            match avg_fixed.clone() {
                Some(ref version) => {
                    if let Some(ref v) = a.fixed {
                        let cmp = alpm::vercmp(version.to_string(), v.to_string());
                        if let Ordering::Greater = cmp {
                            avg_fixed = a.fixed.clone();
                        }
                    }
                }
                None => avg_fixed = a.fixed.clone(),
            }

            if a.severity > avg_severity {
                avg_severity = a.severity;
            }

            if a.status > avg_status {
                avg_status = a.status;
            }
        }

        let avg = avg::AVG {
            issues: avg_issues,
            fixed: avg_fixed,
            severity: avg_severity,
            status: avg_status,
        };
        avgs.insert(pkg.to_string(), avg);
    }

    avgs
}

#[test]
fn test_merge_avgs() {
    let mut avgs: BTreeMap<String, Vec<_>> = BTreeMap::new();

    let avg1 = avg::AVG {
        issues: vec![
            ("CVE-1".to_string(), enums::Severity::Unknown),
            ("CVE-2".to_string(), enums::Severity::Unknown),
        ],
        fixed: Some("1.0.0".to_string()),
        severity: enums::Severity::Unknown,
        status: enums::Status::Fixed,
    };

    let avg2 = avg::AVG {
        issues: vec![
            ("CVE-1".to_string(), enums::Severity::Unknown),
            ("CVE-2".to_string(), enums::Severity::Unknown),
        ],
        fixed: Some("0.9.8".to_string()),
        severity: enums::Severity::High,
        status: enums::Status::Testing,
    };

    assert!(enums::Severity::Critical > enums::Severity::High);

    avgs.insert("package".to_string(), vec![avg1.clone(), avg2.clone()]);

    avgs.insert("package2".to_string(), vec![avg1, avg2]);

    let merged = merge_avgs(&avgs);

    assert_eq!(2, merged.len());
    assert_eq!(
        4,
        merged
            .get(&"package".to_string())
            .expect("'package' key not found")
            .issues
            .len()
    );
    assert_eq!(
        enums::Severity::High,
        merged
            .get(&"package".to_string())
            .expect("'package' key not found")
            .severity
    );
    assert_eq!(
        enums::Status::Testing,
        merged
            .get(&"package".to_string())
            .expect("'package' key not found")
            .status
    );
}

/// Print a list of `avg::AVG`
fn print_avgs(options: &Options, avgs: &BTreeMap<String, avg::AVG>) {
    let mut t = term::stdout().expect("term::stdout failed");
    for (pkg, avg) in avgs {
        match avg.fixed {
            Some(ref v) if avg.status != enums::Status::Vulnerable => {
                // Quiet option
                if options.quiet != 0 {
                    t.fg(avg.severity.to_color()).expect("term::fg failed");
                    if options.quiet >= 2 {
                        writeln!(t, "{}", pkg).expect("term::writeln failed");
                    } else if options.quiet == 1 {
                        writeln!(t, "{}>={}", pkg, v).expect("term::writeln failed");
                    }
                    t.reset().expect("term::stdout failed");
                } else {
                    match options.format {
                        Some(ref f) => {
                            t.fg(term::color::RED).expect("term::color::RED failed");
                            writeln!(
                                t,
                                "{}",
                                f.replace("%n", pkg.as_str()).replace(
                                    "%c",
                                    avg.issues.iter().map(|issue| &issue.0).join(",").as_str(),
                                )
                            )
                            .expect("term::writeln failed");
                            t.reset().expect("term::stdout failed");
                        }
                        None => {
                            print_avg_colored(&mut t, pkg, avg);
                            // Colored update
                            if avg.status == enums::Status::Testing {
                                // Print: Update to {} for testing repos!"
                                print!(" Update to");
                                t.attr(term::Attr::Bold).expect("term::attr failed");
                                t.fg(term::color::GREEN).expect("term::fg failed");
                                write!(t, " {}", v).expect("term::writeln failed");
                                t.reset().expect("term::stdout failed");
                                println!(" from testing repos!");
                            } else if avg.status == enums::Status::Fixed {
                                // Print: Update to {}!
                                print!(" Update to");
                                t.attr(term::Attr::Bold).expect("term::attr failed");
                                t.fg(term::color::GREEN).expect("term::fg failed");
                                writeln!(t, " {}!", v).expect("term::writeln failed");
                                t.reset().expect("term::stdout failed");
                            }
                        }
                    }
                }
            }
            _ => {
                if !options.upgradable_only {
                    if options.quiet > 0 {
                        t.fg(avg.severity.to_color()).expect("term::fg failed");
                        writeln!(t, "{}", pkg).expect("term::writeln failed");
                        t.reset().expect("term::stdout failed");
                    } else {
                        match options.format {
                            Some(ref f) => {
                                t.fg(avg.severity.to_color()).expect("term::fg failed");
                                writeln!(
                                    t,
                                    "{}",
                                    f.replace("%n", pkg.as_str()).replace(
                                        "%c",
                                        avg.issues.iter().map(|issue| &issue.0).join(",").as_str(),
                                    )
                                )
                                .expect("term::writeln failed");
                                t.reset().expect("term::stdout failed");
                            }
                            None => {
                                print_avg_colored(&mut t, pkg, avg);
                                println!();
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Prints "Package {pkg} is affected by {issues}. {severity}." colored
fn print_avg_colored(t: &mut Box<term::StdoutTerminal>, pkg: &String, avg: &avg::AVG) {
    t.reset().expect("term::stdout failed");
    // Bold package
    print!("Package");
    t.attr(term::Attr::Bold).expect("term::attr failed");
    write!(t, " {}", pkg).expect("term::writeln failed");
    // Normal "is affected by"
    t.reset().expect("term::stdout failed");
    print!(" is affected by");
    // Colored issues
    if let Some((first, elements)) = avg.issues.split_first() {
        t.fg(first.1.to_color()).expect("term::fg failed");
        write!(t, " {}", first.0).expect("term::write failed");
        for issue in elements {
            t.fg(issue.1.to_color()).expect("term::fg failed");
            write!(t, ", {}", issue.0).expect("term::write failed");
        }
    }
    t.reset().expect("term::stdout failed");
    print!(".");
    // Colored severity
    t.fg(avg.severity.to_color()).expect("term::fg failed");
    write!(t, " {}.", avg.severity).expect("term::write failed");
    t.reset().expect("term::stdout failed");
}

#[test]
fn test_print_avgs() {
    let mut avgs: BTreeMap<String, Vec<_>> = BTreeMap::new();

    let avg1 = avg::AVG {
        issues: vec![
            ("CVE-1".to_string(), enums::Severity::Unknown),
            ("CVE-2".to_string(), enums::Severity::Low),
            ("CVE-3".to_string(), enums::Severity::Medium),
        ],
        fixed: Some("1.0.0".to_string()),
        severity: enums::Severity::Unknown,
        status: enums::Status::Fixed,
    };

    let avg2 = avg::AVG {
        issues: vec![
            ("CVE-1".to_string(), enums::Severity::High),
            ("CVE-2".to_string(), enums::Severity::Critical),
        ],
        fixed: Some("0.9.8".to_string()),
        severity: enums::Severity::High,
        status: enums::Status::Testing,
    };

    avgs.insert("package".to_string(), vec![avg1.clone(), avg2.clone()]);

    avgs.insert("package2".to_string(), vec![avg1, avg2]);

    let merged = merge_avgs(&avgs);

    let options = Options {
        format: None,
        quiet: 0,
        upgradable_only: false,
    };

    print_avgs(&options, &merged);
}

