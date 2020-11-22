use crate::enums::{Color, Severity, Status};
use alpm::{Alpm, Db, Version};
use atty::Stream;
use clap::{load_yaml, App};
use curl::easy::Easy;
use log::{debug, info};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::default::Default;
use std::io;
use std::process::exit;
use std::str;
use term::terminfo::TermInfo;
use term::{color, Attr};
use term::{StdoutTerminal, TerminfoTerminal};

mod enums;

const WEBSITE: &str = "https://security.archlinux.org";

#[derive(Default)]
struct Options {
    color: enums::Color,
    format: Option<String>,
    quiet: u64,
    recursive: u64,
    upgradable_only: bool,
    show_testing: bool,
    show_cve: bool,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct Avgs {
    avgs: Vec<Avg>,
}

#[derive(Deserialize, Clone, Default)]
struct Avg {
    packages: Vec<String>,
    status: Status,
    #[serde(rename = "type")]
    kind: String,
    severity: Severity,
    fixed: Option<String>,
    issues: Vec<String>,
}

#[derive(PartialOrd, Ord, PartialEq, Eq)]
struct Affected {
    package: String,
    cves: Vec<String>,
    severity: Severity,
    status: Status,
    fixed: Option<String>,
    kind: Vec<String>,
}

fn main() {
    env_logger::init();

    let yaml = load_yaml!("cli.yml");
    let args = App::from_yaml(yaml).get_matches();

    let options = Options {
        color: args
            .value_of("color")
            .unwrap()
            .parse()
            .expect("parse::<Color> failed"),
        format: {
            match args.value_of("format") {
                Some(f) => Some(f.to_string()),
                None => None,
            }
        },
        quiet: args.occurrences_of("quiet"),
        recursive: args.occurrences_of("recursive"),
        upgradable_only: args.is_present("upgradable"),
        show_testing: args.is_present("testing"),
        show_cve: args.is_present("show-cve"),
    };

    let avgs = get_avg_json();
    let avgs: Avgs = serde_json::from_str(&avgs).expect("failed to parse json");

    let dbpath = args.value_of("dbpath").unwrap();
    let pacman = Alpm::new("/", dbpath).expect("Alpm::new() failed");
    let db = pacman.localdb();

    let mut affected = BTreeMap::new();

    for avg in &avgs.avgs {
        if avg.status == Status::NotAffected {
            continue;
        }

        for pkg in &avg.packages {
            if !system_is_affected(db, pkg, &avg) {
                continue;
            }

            let aff = Affected {
                package: pkg.to_string(),
                cves: Vec::new(),
                kind: Vec::new(),
                severity: avg.severity,
                status: Status::Unknown,
                fixed: None,
            };

            let aff = affected.entry(pkg.as_str()).or_insert(aff);
            aff.severity = aff.severity.max(avg.severity);
            aff.cves.extend(avg.issues.clone());
            aff.kind.push(avg.kind.clone());
            aff.status = avg.status;
            if aff.fixed.as_ref().map(|f| Version::new(f.as_str()))
                < avg.fixed.as_ref().map(|f| Version::new(f.as_str()))
            {
                aff.fixed = avg.fixed.clone();
            }

            aff.kind.sort_unstable();
            aff.kind.dedup()
        }
    }

    print_all_affected(&options, &affected, db);
}

fn get_avg_json() -> String {
    let mut avgs = String::new();
    info!("Downloading AVGs...");
    let avgs_url = format!("{}/issues/all.json", WEBSITE);

    let mut easy = Easy::new();
    easy.fail_on_error(true)
        .expect("curl::Easy::fail_on_error failed");
    easy.follow_location(true)
        .expect("curl::Easy::follow_location failed");
    easy.url(&avgs_url).expect("curl::Easy::url failed");
    let mut transfer = easy.transfer();
    transfer
        .write_function(|data| {
            avgs.push_str(str::from_utf8(data).expect("str conversion failed"));
            Ok(data.len())
        })
        .expect("write_function failed");
    if transfer.perform().is_err() {
        println!(
            "Cannot fetch data from {}, please check your network connection!",
            WEBSITE
        );
        exit(1)
    }
    drop(transfer);
    avgs
}

fn get_required_by(db: Db, pkg: &str) -> Vec<String> {
    db.pkg(pkg)
        .unwrap()
        .required_by()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn get_required_by_recursive(db: Db, pkg: &str) -> Vec<String> {
    let mut pkgs = Vec::new();
    let mut seen = HashSet::new();
    _get_required_by_recursive(db, pkg, &mut pkgs, &mut seen);
    pkgs
}

fn _get_required_by_recursive(
    db: alpm::Db,
    pkg: &str,
    pkgs: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    let new_pkgs = db.pkg(pkg).unwrap().required_by();
    seen.insert(pkg.to_string());

    for pkg in &new_pkgs {
        if !seen.contains(pkg) {
            _get_required_by_recursive(db, pkg, pkgs, seen)
        }
    }

    pkgs.extend(new_pkgs);
}

/// Given a package and an `avg::AVG`, returns true if the system is affected
fn system_is_affected(db: Db, pkg: &str, avg: &Avg) -> bool {
    let pkg = if let Ok(pkg) = db.pkg(pkg) {
        info!(
            "Found installed version {} for package {}",
            pkg.version(),
            pkg.name(),
        );
        pkg
    } else {
        debug!("Package {} not installed", pkg);
        return false;
    };

    if let Some(ref fixed) = avg.fixed {
        info!("Comparing with fixed version {}", fixed);
        pkg.version() < fixed
    } else {
        true
    }
}

/// Print a single Affected
fn print_affected(options: &Options, t: &mut term::StdoutTerminal, aff: &Affected, db: Db) {
    match aff.fixed {
        Some(ref v) if aff.status != Status::Vulnerable => {
            // Quiet option
            if options.quiet >= 1 {
                write_with_colours(
                    t,
                    &aff.package,
                    options,
                    Some(aff.severity.to_color()),
                    None,
                );

                if options.quiet == 1 {
                    write!(t, ">=").expect("term::write failed");
                    write_with_colours(t, v, options, Some(term::color::GREEN), None);
                }
            } else {
                match options.format {
                    Some(ref f) => {
                        print_affected_formatted(t, aff, options, f, db);
                    }
                    None => {
                        print_affected_colored(t, aff, options, db);
                    }
                }
            }

            writeln!(t).expect("term::writeln failed");
        }

        _ if !options.upgradable_only => {
            if options.quiet > 0 {
                write_with_colours(
                    t,
                    &aff.package,
                    options,
                    Some(aff.severity.to_color()),
                    None,
                );
            } else if let Some(ref f) = options.format {
                print_affected_formatted(t, aff, options, f, db);
            } else {
                print_affected_colored(t, aff, options, db);
            }

            writeln!(t).expect("term::writeln failed");
        }
        _ => (),
    }
}

// Print a list of Affected
fn print_all_affected(options: &Options, affected: &BTreeMap<&str, Affected>, db: Db) {
    let fake_term = TermInfo {
        names: vec![],
        bools: HashMap::new(),
        numbers: HashMap::new(),
        strings: HashMap::new(),
    };

    let mut t = match term::stdout() {
        Some(x) => x,
        None => Box::new(TerminfoTerminal::new_with_terminfo(io::stdout(), fake_term))
            as Box<StdoutTerminal>,
    };

    for aff in affected.values() {
        print_affected(options, t.as_mut(), aff, db);
    }
}

/// Prints "Package {pkg} is affected by {issues}. {severity}!" colored
fn print_affected_colored(t: &mut term::StdoutTerminal, aff: &Affected, options: &Options, db: Db) {
    // Bold package
    write!(t, "Package ").expect("term::write failed");
    write_with_colours(t, &aff.package, options, None, Some(term::Attr::Bold));
    // Normal "is affected by {issues}"
    write!(t, " is affected by {}. ", aff.kind.join(", ")).expect("term::write failed");
    if options.show_cve {
        write!(t, "({}). ", aff.cves.join(",")).expect("term::write failed");
    }

    if options.recursive != 0 {
        let required_by = if options.recursive == 1 {
            get_required_by(db, &aff.package)
        } else {
            get_required_by_recursive(db, &aff.package)
        };

        if !required_by.is_empty() {
            write!(t, "It's required by {}. ", required_by.join(", ")).expect("term::write failed");
        }
    }

    // Colored severit
    write_with_colours(
        t,
        &aff.severity.to_string(),
        options,
        Some(aff.severity.to_color()),
        None,
    );
    write!(t, "!").expect("term::write failed");

    if let Some(ref version) = aff.fixed {
        if aff.status == Status::Fixed {
            // Print: Update to {}!
            write!(t, " Update to at least ").expect("term::write failed");
            write_with_colours(t, version, options, Some(color::GREEN), Some(Attr::Bold));
            write!(t, "!").expect("term::write failed");
        } else if aff.status == Status::Testing && options.show_testing {
            // Print: Update to {} from the testing repos!"
            write!(t, " Update to at least").expect("term::write failed");
            write_with_colours(t, version, options, Some(color::GREEN), Some(Attr::Bold));
            write!(t, " from the testing repos!").expect("term::write failed");
        }
    }
}

/// Prints output formatted as the user wants
fn print_affected_formatted(
    t: &mut term::StdoutTerminal,
    aff: &Affected,
    options: &Options,
    f: &str,
    db: Db,
) {
    let mut chars = f.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '%' => match chars.peek() {
                Some('%') => {
                    write!(t, "%").expect("term::write failed");
                    chars.next();
                }
                Some('r') => {
                    write!(
                        t,
                        "{}",
                        get_required_by(db, &aff.package).join(",").as_str()
                    )
                    .expect("term::write failed");
                    chars.next();
                }
                Some('n') => {
                    write_with_colours(
                        t,
                        &aff.package,
                        options,
                        Some(aff.severity.to_color()),
                        None,
                    );
                    chars.next();
                }
                Some('c') => {
                    write!(t, "{}", aff.cves.join(",")).expect("term::write failed");
                    chars.next();
                }
                Some('v') => {
                    if let Some(ref version) = aff.fixed {
                        if aff.status == Status::Fixed
                            || (aff.status == Status::Testing && options.show_testing)
                        {
                            write_with_colours(
                                t,
                                version,
                                options,
                                Some(color::GREEN),
                                Some(Attr::Bold),
                            );
                        }
                    }
                    chars.next();
                }
                Some('t') => {
                    if !aff.kind.is_empty() {
                        write!(t, "{}", aff.kind.join(", ")).expect("term::write failed");
                    }
                    chars.next();
                }
                Some(x) => {
                    debug!("Unknown placeholder {}", x);
                    chars.next();
                }
                None => {}
            },
            x => {
                write!(t, "{}", x).expect("term::write failed");
            }
        }
    }
}

fn write_with_colours(
    t: &mut term::StdoutTerminal,
    text: &str,
    options: &Options,
    color: Option<term::color::Color>,
    attribute: Option<term::Attr>,
) {
    let show_colors = match options.color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => t.supports_color() && atty::is(Stream::Stdout),
    };

    if show_colors {
        if let Some(c) = color {
            t.fg(c).expect("term::fg failed");
        }
        if let Some(a) = attribute {
            t.attr(a).expect("term::attr failed");
        }
    }

    write!(t, "{}", text).expect("term::write failed");

    if show_colors {
        t.reset().expect("term::stdout failed");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(test)]
    mod test {
        use super::*;

        const ROOT_DIR: &str = "/";
        const DB_PATH: &str = "/var/lib/pacman";

        #[test]
        fn test_system_is_affected() {
            let pacman = alpm::Alpm::new(ROOT_DIR, DB_PATH).expect("Alpm::new failed");
            let db = pacman.localdb();

            let avg1 = Avg {
                issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
                fixed: Some("2000.0.0".to_string()),
                severity: enums::Severity::Unknown,
                status: enums::Status::Unknown,
                packages: Vec::new(),
                kind: String::new(),
            };

            assert_eq!(false, system_is_affected(db, "filesystem", &avg1));

            let avg2 = Avg {
                issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
                fixed: Some("3009.0.0".to_string()),
                severity: enums::Severity::Unknown,
                status: enums::Status::Unknown,
                packages: Vec::new(),
                kind: String::new(),
            };

            assert!(system_is_affected(db, "filesystem", &avg2));
        }
    }
}
