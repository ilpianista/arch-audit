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

    let mut infos: HashMap<String, Vec<_>> = HashMap::new();
    {
        let json = Json::from_str(&avgs).unwrap();

        for avg in json.as_array().unwrap() {
            let packages = avg["packages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_string().unwrap().to_string())
                .collect::<Vec<_>>();

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
                    match infos.entry(p) {
                            Occupied(c) => c.into_mut(),
                            Vacant(c) => c.insert(vec![]),
                        }
                        .push(info.clone());
                }
            }
        }
    }

    let pacman = match args.value_of("dbpath") {
        Some(path) => alpm::Alpm::with_dbpath(path.to_string()).unwrap(),
        None => alpm::Alpm::new().unwrap(),
    };

    for (pkg, cves) in infos {
        let pkg_cves = get_asas_for_package_by_version(&pacman, &pkg, &cves);

        let (relevant_cves, version) = cves_with_relevant_version(pkg_cves, &pacman);

        if !relevant_cves.is_empty() {
            print_asa(&options, &pkg, relevant_cves, version);
        }
    }
}

/// gets a map from version to ASAs for a specific package, returns list of CVEs for that
/// package and a version, which is the most updated
fn cves_with_relevant_version(pkg_cves: HashMap<Option<String>, Vec<ASA>>,
                              pacman: &alpm::Alpm)
                              -> (Vec<String>, Option<String>) {
    let mut cves: Vec<String> = vec![];
    // the newest version, which fixes all/most ? cves
    let mut version: Option<String> = None;
    for (v, asas) in pkg_cves {
        for asa in asas {
            for cve in asa.cve {
                cves.push(cve);
            }
        }
        match v {
            Some(ref v) => {
                version = match version {
                    None => Some(v.clone()),
                    Some(ref vv) => {
                        match pacman.vercmp(v.clone(), vv.clone()).unwrap() {
                            Ordering::Greater => Some(v.clone()),
                            _ => version.clone(),
                        }
                    }
                }
            }
            _ => {}
        }
    }
    (cves, version)
}

#[test]
fn test_cves_with_relevant_version() {
    let mut map = HashMap::new();
    map.insert(Some("1.0".to_string()),
               vec![ASA {
                        cve: vec!["a".to_string(), "b".to_string()],
                        version: Some("1.0".to_string()),
                    }]);
    map.insert(Some("2.0".to_string()),
               vec![ASA {
                        cve: vec!["c".to_string()],
                        version: Some("2.0".to_string()),
                    }]);
    map.insert(Some("3.0".to_string()),
               vec![ASA {
                        cve: vec![],
                        version: Some("3.0".to_string()),
                    }]);

    let pacman = alpm::Alpm::new().unwrap();
    let (mut cves, version) = cves_with_relevant_version(map, &pacman);

    cves.sort();
    assert_eq!(cves,
               vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    assert_eq!(version, Some("3.0".to_string()));
}

/// creates a map between version and ASAs from a list of ASAs
fn get_asas_for_package_by_version(pacman: &alpm::Alpm,
                                   pkg: &String,
                                   cves: &Vec<ASA>)
                                   -> HashMap<Option<String>, Vec<ASA>> {
    let mut pkg_cves: HashMap<Option<String>, Vec<ASA>> = HashMap::new();
    match pacman.query_package_version(pkg.clone()) {
        Ok(v) => {
            info!("Found installed version {} for package {}", v, pkg);
            for cve in cves {
                match cve.version {
                    Some(ref version) => {
                        info!("Comparing with fixed version {}", version);
                        match pacman.vercmp(v.clone(), version.clone()).unwrap() {
                            Ordering::Less => {
                                match pkg_cves.entry(Some(version.clone())) {
                                        Occupied(c) => c.into_mut(),
                                        Vacant(c) => c.insert(vec![]),
                                    }
                                    .push(cve.clone());
                            }
                            _ => {}
                        };
                    }
                    None => {
                        match pkg_cves.entry(None) {
                                Occupied(c) => c.into_mut(),
                                Vacant(c) => c.insert(vec![]),
                            }
                            .push(cve.clone());
                    }
                };
            }
        }
        Err(_) => debug!("Package {} not installed", pkg),
    }
    pkg_cves
}

fn print_asa(options: &Options, pkgname: &String, cve: Vec<String>, version: Option<String>) {
    let msg = format!("Package {} is affected by {:?}", pkgname, cve);

    match version {
        Some(v) => {
            if options.quiet == 1 {
                println!("{}>={}", pkgname, v);
            } else if options.quiet >= 2 {
                println!("{}", pkgname);
            } else {
                match options.format {
                    Some(ref f) => {
                        println!("{}",
                                 f.replace("%n", pkgname)
                                     .replace("%c", cve.iter().join(",").as_str()))
                    }
                    None => println!("{}. Update to {}!", msg, v),
                }
            }
        }
        None => {
            if !options.upgradable_only {
                if options.quiet > 0 {
                    println!("{}", pkgname);
                } else {
                    match options.format {
                        Some(ref f) => {
                            println!("{}",
                                     f.replace("%n", pkgname)
                                         .replace("%c", cve.iter().join(",").as_str()))
                        }
                        None => println!("{}. VULNERABLE!", msg),
                    }
                }
            }
        }
    }
}
