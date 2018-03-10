extern crate alpm;
#[macro_use]
extern crate clap;
extern crate curl;
extern crate env_logger;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate serde_json;

use clap::App;
use curl::easy::Easy;
use itertools::Itertools;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::default::Default;
use std::process::exit;
use std::str;

mod avg;
mod enums;

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
    env_logger::init().expect("env_logger failed");

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
        let avgs_url = "https://security.archlinux.org/issues/all.json";

        let mut easy = Easy::new();
        easy.url(avgs_url).expect("curl::Easy::url failed");
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
                println!("Cannot fetch data, please check your network connection!");
                exit(1)
            }
        };
    }

    let pacman = match args.value_of("dbpath") {
        Some(path) => {
            alpm::Alpm::with_dbpath(path.to_string()).expect("alpm::Alpm::with_dbpath failed")
        }
        None => alpm::Alpm::new().expect("alpm::Alpm::new failed"),
    };

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

            if !package_is_installed(&pacman, &packages) {
                continue;
            }

            let info = to_avg(avg);

            if info.status != enums::Status::NotAffected {
                for p in packages {
                    match cves.entry(p) {
                        Occupied(c) => c.into_mut(),
                        Vacant(c) => c.insert(vec![]),
                    }.push(info.clone());
                }
            }
        }
    }

    let mut affected_avgs: BTreeMap<String, Vec<_>> = BTreeMap::new();
    for (pkg, avgs) in cves {
        for avg in &avgs {
            if system_is_affected(&pacman, &pkg, avg) {
                match affected_avgs.entry(pkg.clone()) {
                    Occupied(c) => c.into_mut(),
                    Vacant(c) => c.insert(vec![]),
                }.push(avg.clone());
            }
        }
    }

    let merged = merge_avgs(&pacman, &affected_avgs);
    print_avgs(&options, &merged);
}

/// Converts a JSON to an `avg::AVG`
fn to_avg(data: &Value) -> avg::AVG {
    avg::AVG {
        issues: data["issues"]
            .as_array()
            .expect("Value::as_array failed")
            .iter()
            .map(|s| s.as_str().expect("Value::as_str failed").to_string())
            .collect(),
        fixed: match data["fixed"].as_str() {
            Some(s) => Some(s.to_string()),
            None => None,
        },
        severity: data["severity"]
            .as_str()
            .expect("Value::as_str failed")
            .to_string()
            .parse::<enums::Severity>()
            .expect("parse::<Severity> failed"),
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
    ).expect("serde_json::from_str failed");

    let avg1 = to_avg(&json);
    assert_eq!(2, avg1.issues.len());
    assert_eq!(Some("1.0".to_string()), avg1.fixed);
    assert_eq!(enums::Severity::High, avg1.severity);
    assert_eq!(enums::Status::NotAffected, avg1.status);

    let json: Value = serde_json::from_str(
        "{\"issues\": [\"CVE-1\"], \"fixed\": null, \
                               \"severity\": \"Low\", \"status\": \"Vulnerable\"}",
    ).expect("serde_json::from_str failed");

    let avg2 = to_avg(&json);
    assert_eq!(1, avg2.issues.len());
    assert_eq!(None, avg2.fixed);
    assert_eq!(enums::Severity::Low, avg2.severity);
    assert_eq!(enums::Status::Vulnerable, avg2.status);
}

/// Given a package and an `avg::AVG`, returns true if the system is affected
fn system_is_affected(pacman: &alpm::Alpm, pkg: &str, avg: &avg::AVG) -> bool {
    match pacman.query_package_version(pkg.clone()) {
        Ok(v) => {
            info!("Found installed version {} for package {}", v, pkg);
            match avg.fixed {
                Some(ref version) => {
                    info!("Comparing with fixed version {}", version);
                    let cmp = pacman.vercmp(v.clone(), version.clone()).expect(
                        "Alpm::vercmp failed",
                    );
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
    let pacman = alpm::Alpm::new().expect("Alpm::new failed");

    let avg1 = avg::AVG {
        issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
        fixed: Some("1.0.0".to_string()),
        severity: enums::Severity::Unknown,
        status: enums::Status::Unknown,
    };

    assert_eq!(
        false,
        system_is_affected(&pacman, &"pacman".to_string(), &avg1)
    );

    let avg2 = avg::AVG {
        issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
        fixed: Some("7.0.0".to_string()),
        severity: enums::Severity::Unknown,
        status: enums::Status::Unknown,
    };

    assert!(system_is_affected(&pacman, &"pacman".to_string(), &avg2));
}

/// Given a list of package names, returns true when at least one is installed
fn package_is_installed(pacman: &alpm::Alpm, packages: &[String]) -> bool {
    for pkg in packages {
        match pacman.query_package_version(pkg.as_str()) {
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
    let pacman = alpm::Alpm::new().expect("Alpm::new failed");

    let packages = vec!["pacman".to_string(), "pac".to_string()];
    assert!(package_is_installed(&pacman, &packages));

    let packages = vec!["pac".to_string()];
    assert_eq!(false, package_is_installed(&pacman, &packages));
}

/// Merge a list of `avg::AVG` into a single `avg::AVG` using major version as version
fn merge_avgs(
    pacman: &alpm::Alpm,
    cves: &BTreeMap<String, Vec<avg::AVG>>,
) -> BTreeMap<String, avg::AVG> {
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
                        let cmp = pacman.vercmp(version.to_string(), v.to_string()).expect(
                            "Alpm::vercmp failed",
                        );
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
        issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
        fixed: Some("1.0.0".to_string()),
        severity: enums::Severity::Unknown,
        status: enums::Status::Fixed,
    };

    let avg2 = avg::AVG {
        issues: vec!["CVE-4".to_string(), "CVE-10".to_string()],
        fixed: Some("0.9.8".to_string()),
        severity: enums::Severity::High,
        status: enums::Status::Testing,
    };

    assert!(enums::Severity::Critical > enums::Severity::High);

    avgs.insert("package".to_string(), vec![avg1.clone(), avg2.clone()]);

    avgs.insert("package2".to_string(), vec![avg1, avg2]);

    let pacman = alpm::Alpm::new().expect("Alpm::new failed");
    let merged = merge_avgs(&pacman, &avgs);

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
    for (pkg, avg) in avgs {
        match avg.fixed {
            Some(ref v) if avg.status != enums::Status::Vulnerable => {
                if options.quiet >= 2 {
                    println!("{}", pkg);
                } else if options.quiet == 1 {
                    println!("{}>={}", pkg, v);
                } else {
                    match options.format {
                        Some(ref f) => {
                            println!(
                                "{}",
                                f.replace("%n", pkg.as_str()).replace(
                                    "%c",
                                    avg.issues
                                        .iter()
                                        .join(",")
                                        .as_str(),
                                )
                            )
                        }
                        None => {
                            let msg = format!(
                                "Package {} is affected by {}. {}!",
                                pkg,
                                avg.issues.join(", "),
                                avg.severity
                            );

                            if avg.status == enums::Status::Testing {
                                println!("{}. Update to {} from testing repos!", msg, v)
                            } else if avg.status == enums::Status::Fixed {
                                println!("{}. Update to {}!", msg, v)
                            } else {
                                println!("{}", msg)
                            }
                        }
                    }
                }
            }
            _ => {
                if !options.upgradable_only {
                    if options.quiet > 0 {
                        println!("{}", pkg);
                    } else {
                        match options.format {
                            Some(ref f) => {
                                println!(
                                    "{}",
                                    f.replace("%n", pkg.as_str()).replace(
                                        "%c",
                                        avg.issues
                                            .iter()
                                            .join(",")
                                            .as_str(),
                                    )
                                )
                            }
                            None => {
                                println!(
                                    "Package {} is affected by {}. {}!",
                                    pkg,
                                    avg.issues.join(", "),
                                    avg.severity
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
