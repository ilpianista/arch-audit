extern crate alpm;
extern crate clap;
extern crate curl;
extern crate env_logger;
extern crate itertools;
extern crate json;
#[macro_use]
extern crate log;
extern crate select;

use clap::{Arg, App};
use curl::easy::Easy;
use itertools::Itertools;
use select::document::Document;
use select::predicate::Name;
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

    let args = App::new("arch-audit")
        .version("0.1.4")
        .arg(Arg::with_name("dbpath")
            .short("b")
            .long("dbpath")
            .takes_value(true)
            .help("Set an alternate database location"))
        .arg(Arg::with_name("format")
            .short("f")
            .long("format")
            .takes_value(true)
            .help("Specify a format to control the output. Placeholders are %n (pkgname) and %c \
                   (CVEs)"))
        .arg(Arg::with_name("quiet")
            .short("q")
            .long("quiet")
            .multiple(true)
            .help("Show only vulnerable package names and their versions"))
        .arg(Arg::with_name("upgradable")
            .short("u")
            .long("upgradable")
            .help("Show only packages that have already been fixed"))
        .get_matches();

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

    let mut wikipage = String::new();
    {
        info!("Downloading CVE wiki page...");
        let wikipage_url = "https://wiki.archlinux.org/api.\
                            php?format=json&action=parse&page=CVE&section=5";

        let mut easy = Easy::new();
        easy.url(wikipage_url).unwrap();
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
                wikipage.push_str(str::from_utf8(data).unwrap());
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
        let json = json::parse(wikipage.as_str()).unwrap();
        let document = Document::from(json["parse"]["text"]["*"].as_str().unwrap());

        for tr in document.find(Name("tbody")).find(Name("tr")).iter() {
            let tds = tr.find(Name("td"));

            match tds.first() {
                Some(td) => {
                    let mut next = tds.next().next();
                    let pkgname = next.first().unwrap().text().trim().to_string();
                    next = next.next().next().next().next().next().next();
                    let info = ASA {
                        cve: td.text()
                            .split_whitespace()
                            .filter(|s| s.starts_with("CVE"))
                            .map(|s| s.to_string())
                            .collect(),
                        version: {
                            let v = next.first().unwrap().text().trim().to_string();
                            if !v.is_empty() && v != "?".to_string() && v != "-".to_string() {
                                Some(v)
                            } else {
                                None
                            }
                        },
                    };
                    next = next.next().next().next().next();
                    let status = next.first().unwrap().text().trim().to_string();

                    if !status.starts_with("Not Affected") {
                        match infos.entry(pkgname) {
                                Occupied(c) => c.into_mut(),
                                Vacant(c) => c.insert(vec![]),
                            }
                            .push(info);
                    }
                }
                None => {}
            };
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
