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
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::default::Default;
use std::process::exit;
use std::str;


#[derive(Debug, Clone)]
struct ASA {
    cve: Vec<String>,
    version: Option<String>,
}

impl Default for ASA {
    fn default() -> ASA {
        ASA {
            cve: vec![],
            version: None,
        }
    }
}

#[derive(Debug)]
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

    let mut cves: HashMap<String, Vec<_>> = HashMap::new();
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

            let info = ASA {
                cve: avg["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_string().unwrap().to_string())
                    .collect(),
                version: match avg["fixed"].as_string() {
                    Some(s) => Some(s.to_string()),
                    None => None,
                },
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

    let mut affected_cves: HashMap<String, Vec<_>> = HashMap::new();
    for (pkg, asas) in cves {
        for asa in &asas {
            if system_is_affected(&pacman, &pkg, &asa) {
                match affected_cves.entry(pkg.clone()) {
                        Occupied(c) => c.into_mut(),
                        Vacant(c) => c.insert(vec![]),
                    }
                    .push(asa.clone());
            }
        }
    }

    let merged = merge_asas(&pacman, &affected_cves);
    print_asas(&options, &merged);
}

/// Given a package and an ASA, returns true if the system is affected
fn system_is_affected(pacman: &alpm::Alpm, pkg: &String, asa: &ASA) -> bool {
    match pacman.query_package_version(pkg.clone()) {
        Ok(v) => {
            info!("Found installed version {} for package {}", v, pkg);
            match asa.version {
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

    let cve1 = ASA {
        cve: vec!["CVE-1".to_string(), "CVE-2".to_string()],
        version: Some("1.0.0".to_string()),
    };

    assert_eq!(false,
               system_is_affected(&pacman, &"pacman".to_string(), &cve1));

    let cve2 = ASA {
        cve: vec!["CVE-1".to_string(), "CVE-2".to_string()],
        version: Some("7.0.0".to_string()),
    };
    assert!(system_is_affected(&pacman, &"pacman".to_string(), &cve2));
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

/// Merge a list of ASAs into a single ASA using major version as version
fn merge_asas(pacman: &alpm::Alpm, cves: &HashMap<String, Vec<ASA>>) -> HashMap<String, ASA> {
    let mut asas: HashMap<String, ASA> = HashMap::new();
    for (pkg, list) in cves.iter() {
        let mut asa_cve = vec![];
        let mut asa_version: Option<String> = None;

        for a in list.iter() {
            asa_cve.append(&mut a.cve.clone());

            match asa_version.clone() {
                Some(ref version) => {
                    match a.version {
                        Some(ref v) => {
                            match pacman.vercmp(version.to_string(), v.to_string()).unwrap() {
                                Ordering::Greater => asa_version = a.version.clone(),
                                _ => {}
                            }
                        }
                        None => {}
                    }
                }
                None => asa_version = a.version.clone(),
            }
        }

        let asa = ASA {
            cve: asa_cve,
            version: asa_version,
        };
        asas.insert(pkg.to_string(), asa);
    }

    asas
}

#[test]
fn test_merge_asas() {
    let mut affected_cves: HashMap<String, Vec<_>> = HashMap::new();

    let asa1 = ASA {
        cve: vec!["CVE-1".to_string(), "CVE-2".to_string()],
        version: Some("1.0.0".to_string()),
    };

    let asa2 = ASA {
        cve: vec!["CVE-4".to_string(), "CVE-10".to_string()],
        version: Some("0.9.8".to_string()),
    };

    affected_cves.insert("package".to_string(), vec![asa1.clone(), asa2.clone()]);

    affected_cves.insert("package2".to_string(), vec![asa1, asa2]);

    let pacman = alpm::Alpm::new().unwrap();
    let merged = merge_asas(&pacman, &affected_cves);

    assert_eq!(2, merged.len());
    assert_eq!(4, merged.get(&"package".to_string()).unwrap().cve.len());
}

/// Print a list of ASAs
fn print_asas(options: &Options, cves: &HashMap<String, ASA>) {
    for (pkg, asa) in cves {
        let msg = format!("Package {} is affected by {:?}", pkg, asa.cve);

        match asa.version {
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
                                         .replace("%c", asa.cve.iter().join(",").as_str()))
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
                                             .replace("%c", asa.cve.iter().join(",").as_str()))
                            }
                            None => println!("{}. VULNERABLE!", msg),
                        }
                    }
                }
            }
        }
    }
}
