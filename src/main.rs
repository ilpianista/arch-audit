extern crate alpm;
#[macro_use]
extern crate clap;
extern crate curl;
extern crate env_logger;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate rustc_serialize;

use clap::App;
use curl::easy::Easy;
use itertools::Itertools;
use rustc_serialize::json::Json;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::default::Default;
use std::process::exit;
use std::str;
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, PartialOrd)]
enum Severity {
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
            "Critical" => Ok(Severity::Critical),
            "High" => Ok(Severity::High),
            "Medium" => Ok(Severity::Medium),
            "Low" => Ok(Severity::Low),
            _ => Ok(Severity::Unknown),
        }
    }
}

#[derive(Clone, Debug)]
struct AVG {
    issues: Vec<String>,
    fixed: Option<String>,
    severity: Severity,
}

impl Default for AVG {
    fn default() -> AVG {
        AVG {
            issues: vec![],
            fixed: None,
            severity: Severity::Unknown,
        }
    }
}

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
    env_logger::init().unwrap();

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
        let avgs_url = "https://security.archlinux.org/json";

        let mut easy = Easy::new();
        easy.url(avgs_url).unwrap();
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
                avgs.push_str(str::from_utf8(data).unwrap());
                Ok(data.len())
            })
            .unwrap();
        match transfer.perform() {
            Ok(_) => {}
            Err(_) => {
                println!("Cannot fetch data, please check your network connection!");
                exit(1)
            }
        };
    }

    let pacman = match args.value_of("dbpath") {
        Some(path) => alpm::Alpm::with_dbpath(path.to_string()).unwrap(),
        None => alpm::Alpm::new().unwrap(),
    };

    let mut cves: BTreeMap<String, Vec<_>> = BTreeMap::new();
    {
        let json = Json::from_str(&avgs).unwrap();

        for avg in json.as_array().unwrap() {
            let packages = avg["packages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_string().unwrap().to_string())
                .collect::<Vec<_>>();

            if !package_is_installed(&pacman, &packages) {
                continue;
            }

            let info = AVG {
                issues: avg["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_string().unwrap().to_string())
                    .collect(),
                fixed: match avg["fixed"].as_string() {
                    Some(s) => Some(s.to_string()),
                    None => None,
                },
                severity: avg["severity"]
                    .as_string()
                    .unwrap()
                    .to_string()
                    .parse::<Severity>()
                    .unwrap(),
            };

            let status = avg["status"].as_string().unwrap();

            if !status.starts_with("Not affected") {
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
            if system_is_affected(&pacman, &pkg, &avg) {
                match affected_avgs.entry(pkg.clone()) {
                        Occupied(c) => c.into_mut(),
                        Vacant(c) => c.insert(vec![]),
                    }
                    .push(avg.clone());
            }
        }
    }

    let merged = merge_avgs(&pacman, &affected_avgs);
    print_avgs(&options, &merged);
}

/// Given a package and an AVG, returns true if the system is affected
fn system_is_affected(pacman: &alpm::Alpm, pkg: &String, avg: &AVG) -> bool {
    match pacman.query_package_version(pkg.clone()) {
        Ok(v) => {
            info!("Found installed version {} for package {}", v, pkg);
            match avg.fixed {
                Some(ref version) => {
                    info!("Comparing with fixed version {}", version);
                    match pacman.vercmp(v.clone(), version.clone()).unwrap() {
                        Ordering::Less => return true,
                        _ => {}
                    };
                }
                None => return true,
            };
        }
        Err(_) => debug!("Package {} not installed", pkg),
    }

    return false;
}

#[test]
fn test_system_is_affected() {
    let pacman = alpm::Alpm::new().unwrap();

    let avg1 = AVG {
        issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
        fixed: Some("1.0.0".to_string()),
        severity: Severity::Unknown,
    };

    assert_eq!(false,
               system_is_affected(&pacman, &"pacman".to_string(), &avg1));

    let avg2 = AVG {
        issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
        fixed: Some("7.0.0".to_string()),
        severity: Severity::Unknown,
    };
    assert!(system_is_affected(&pacman, &"pacman".to_string(), &avg2));
}

/// Given a list of package names, returns true when at least one is installed
fn package_is_installed(pacman: &alpm::Alpm, packages: &Vec<String>) -> bool {
    for pkg in packages {
        match pacman.query_package_version(pkg.as_str()) {
            Ok(_) => {
                info!("Package {} is installed", pkg);
                return true;
            }
            Err(_) => debug!("Package {} not installed", pkg),
        }
    }
    return false;
}

#[test]
fn test_package_is_installed() {
    let pacman = alpm::Alpm::new().unwrap();

    let packages = vec!["pacman".to_string(), "pac".to_string()];
    assert!(package_is_installed(&pacman, &packages));

    let packages = vec!["pac".to_string()];
    assert_eq!(false, package_is_installed(&pacman, &packages));
}

/// Merge a list of AVGs into a single AVG using major version as version
fn merge_avgs(pacman: &alpm::Alpm, cves: &BTreeMap<String, Vec<AVG>>) -> BTreeMap<String, AVG> {
    let mut avgs: BTreeMap<String, AVG> = BTreeMap::new();
    for (pkg, list) in cves.iter() {
        let mut avg_issues = vec![];
        let mut avg_fixed: Option<String> = None;
        let mut avg_severity = Severity::Unknown;

        for a in list.iter() {
            avg_issues.append(&mut a.issues.clone());

            match avg_fixed.clone() {
                Some(ref version) => {
                    match a.fixed {
                        Some(ref v) => {
                            match pacman.vercmp(version.to_string(), v.to_string()).unwrap() {
                                Ordering::Greater => avg_fixed = a.fixed.clone(),
                                _ => {}
                            }
                        }
                        None => {}
                    }
                }
                None => avg_fixed = a.fixed.clone(),
            }

            if a.severity > avg_severity {
                avg_severity = a.severity.clone();
            }
        }

        let avg = AVG {
            issues: avg_issues,
            fixed: avg_fixed,
            severity: avg_severity,
        };
        avgs.insert(pkg.to_string(), avg);
    }

    avgs
}

#[test]
fn test_merge_avgs() {
    let mut avgs: BTreeMap<String, Vec<_>> = BTreeMap::new();

    let avg1 = AVG {
        issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
        fixed: Some("1.0.0".to_string()),
        severity: Severity::Unknown,
    };

    let avg2 = AVG {
        issues: vec!["CVE-4".to_string(), "CVE-10".to_string()],
        fixed: Some("0.9.8".to_string()),
        severity: Severity::High,
    };

    assert!(Severity::Critical > Severity::High);

    avgs.insert("package".to_string(), vec![avg1.clone(), avg2.clone()]);

    avgs.insert("package2".to_string(), vec![avg1, avg2]);

    let pacman = alpm::Alpm::new().unwrap();
    let merged = merge_avgs(&pacman, &avgs);

    assert_eq!(2, merged.len());
    assert_eq!(4, merged.get(&"package".to_string()).unwrap().issues.len());
    assert_eq!(Severity::High,
               merged.get(&"package".to_string()).unwrap().severity);
}

/// Print a list of AVGs
fn print_avgs(options: &Options, avgs: &BTreeMap<String, AVG>) {
    for (pkg, avg) in avgs {
        let msg = format!("Package {} is affected by {:?}", pkg, avg.issues);

        match avg.fixed {
            Some(ref v) => {
                if options.quiet == 1 {
                    println!("{}>={}", pkg, v);
                } else if options.quiet >= 2 {
                    println!("{}", pkg);
                } else {
                    match options.format {
                        Some(ref f) => {
                            println!("{}",
                                     f.replace("%n", pkg.as_str())
                                         .replace("%c", avg.issues.iter().join(",").as_str()))
                        }
                        None => println!("{}. Update to {}!", msg, v),
                    }
                }
            }
            None => {
                if !options.upgradable_only {
                    if options.quiet > 0 {
                        println!("{}", pkg);
                    } else {
                        match options.format {
                            Some(ref f) => {
                                println!("{}",
                                         f.replace("%n", pkg.as_str())
                                             .replace("%c", avg.issues.iter().join(",").as_str()))
                            }
                            None => println!("{}. {:?} risk!", msg, avg.severity),
                        }
                    }
                }
            }
        }
    }
}
