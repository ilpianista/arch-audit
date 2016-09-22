extern crate alpm;
extern crate curl;
extern crate env_logger;
#[macro_use]
extern crate json;
#[macro_use]
extern crate log;
extern crate select;

use curl::easy::Easy;
use select::document::Document;
use select::predicate::Name;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::str;

#[derive(Debug)]
struct CVEInfo {
    cve: Vec<String>,
    version: Option<String>,
}

fn main() {
    env_logger::init().unwrap();

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
                let pkgname = tds.next().next().first().unwrap().text().trim().to_string();
                let info = CVEInfo {
                    cve: td.text().split_whitespace().filter(|s| s.starts_with("CVE")).map(|s| s.to_string()).collect(),
                    version: {
                        let v = tds.next().next().next().next().next().next().next().next().first().unwrap().text().trim().to_string();
                        if !v.is_empty() && v != "?".to_string() { Some(v) } else { None }
                    },
                };

                if !infos.contains_key(&pkgname) {
                    infos.insert(pkgname.clone(), Vec::new());
                }

                infos.get_mut(&pkgname).unwrap().push(info);
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
                                Ordering::Less => { println!("Package {} is affected by {:?}. Update to {}!", pkg, cve.cve, version) },
                                _ => {},
                            };
                        },
                        None => { println!("Package {} is affected by {:?}. VULNERABLE!", pkg, cve.cve) },
                    };
                };
            },
            Err(_) => { debug!("Package {} not installed", pkg) },
        }
    }
}

