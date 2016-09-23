extern crate alpm;
extern crate clap;
extern crate curl;
extern crate env_logger;
#[macro_use]
extern crate json;
#[macro_use]
extern crate log;
extern crate select;

use clap::{Arg, App};
use curl::easy::Easy;
use select::document::Document;
use select::predicate::Name;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::str;

static mut upgradable_only: bool = false;
static mut quiet: bool = false;

#[derive(Debug)]
struct ASA {
    cve: Vec<String>,
    version: Option<String>,
}

fn main() {
    env_logger::init().unwrap();

    let args = App::new("arch-audit")
                        .version("0.1.1")
                        .arg(Arg::with_name("quiet")
                             .short("q")
                             .long("quiet")
                             .help("Show only vulnerable package names and their versions"))
                        .arg(Arg::with_name("upgradable")
                             .short("u")
                             .long("upgradable")
                             .help("Show only packages that have already been fixed"))
                        .get_matches();

    unsafe {
        upgradable_only = args.is_present("upgradable");
        quiet = args.is_present("quiet");
    }

    let mut wikipage = String::new();
    {
        info!("Downloading CVE wiki page...");
        let wikipage_url = "https://wiki.archlinux.org/api.php?format=json&action=parse&page=CVE&section=5";

        let mut easy = Easy::new();
        easy.url(wikipage_url).unwrap();
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            wikipage.push_str(str::from_utf8(data).unwrap());
            Ok(data.len())
        }).unwrap();
        transfer.perform().unwrap();
    }

    let json = json::parse(wikipage.as_str()).unwrap();
    let document = Document::from(json["parse"]["text"]["*"].as_str().unwrap());

    let mut infos: HashMap<String, Vec<_>> = HashMap::new();
    for tr in document.find(Name("tbody")).find(Name("tr")).iter() {
        let tds = tr.find(Name("td"));

        match tds.first() {
            Some(td) => {
                let mut next = tds.next().next();
                let pkgname = next.first().unwrap().text().trim().to_string();
                next = next.next().next().next().next().next().next();
                let info = ASA {
                    cve: td.text().split_whitespace().filter(|s| s.starts_with("CVE")).map(|s| s.to_string()).collect(),
                    version: {
                        let v = next.first().unwrap().text().trim().to_string();
                        if !v.is_empty() && v != "?".to_string() && v != "-".to_string() { Some(v) } else { None }
                    },
                };
                next = next.next().next().next().next();
                let status = next.first().unwrap().text().trim().to_string();

                if !status.starts_with("Invalid") && !status.starts_with("Not Affected") {
                  if !infos.contains_key(&pkgname) {
                      infos.insert(pkgname.clone(), Vec::new());
                  }

                  infos.get_mut(&pkgname).unwrap().push(info);
                }
            },
            None => {},
        };
    }

    let pacman = alpm::Alpm::new().unwrap();
    for (pkg, cves) in infos {
        match pacman.query_package_version(pkg.clone()) {
            Ok(v) => {
                info!("Found installed version {} for package {}", v, pkg);
                for cve in cves {
                    match cve.version {
                        Some(version) => {
                            info!("Comparing with fixed version {}", version);
                            match pacman.vercmp(v.clone(), version.clone()).unwrap() {
                                Ordering::Less => { print_asa(&pkg, &cve.cve, Some(version) ) },
                                _ => {},
                            };
                        },
                        None => { print_asa(&pkg, &cve.cve, None) },
                    };
                };
            },
            Err(_) => { debug!("Package {} not installed", pkg) },
        }
    }
}

fn print_asa(pkgname: &String, cve: &Vec<String>, version: Option<String>) {
    let msg = format!("Package {} is affected by {:?}.", pkgname, cve);

    unsafe {
        match version {
            Some(v) => {
                if quiet {
                    println!("{}>={}", pkgname, v);
                } else {
                    println!("{}. Update to {}!", msg, v);
                }
            }
            None => {
                if !upgradable_only {
                    if quiet {
                        println!("{}", pkgname);
                    } else {
                        println!("{}. VULNERABLE!", msg);
                    }
                }
            }
        }
    }
}
