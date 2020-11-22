use crate::enums::{Severity, Status};
use alpm::{Alpm, Db, Version};
use atty::Stream;
use clap::{load_yaml, App};
use curl::easy::Easy;
use log::{debug, info};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::default::Default;
use std::io;
use std::process::exit;
use std::str;
use term::terminfo::TermInfo;
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

    let mut cves = BTreeMap::new();

    for avg in &avgs.avgs {
        if !package_is_installed(db, &avg.packages) {
            continue;
        }

        if avg.status != Status::NotAffected {
            for pkg in &avg.packages {
                let pkg = pkg.as_str();
                cves.entry(pkg).or_insert_with(Vec::new).push(avg);
            }
        }
    }

    let mut affected_avgs = BTreeMap::new();

    for (pkg, avgs) in cves {
        for avg in avgs.into_iter() {
            if system_is_affected(db, &pkg, avg) {
                affected_avgs
                    .entry(pkg.to_string())
                    .or_insert_with(Vec::new)
                    .push(avg.clone());
            }
        }
    }

    let merged = merge_avgs(&affected_avgs);
    print_avgs(&options, &merged, db);
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

fn get_required_by(db: alpm::Db, pkg: &str) -> Vec<String> {
    db.pkg(pkg)
        .unwrap()
        .required_by()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn get_required_by_recursive(db: alpm::Db, pkg: &str) -> Vec<String> {
    let mut pkgs = Vec::new();
    let new_pkgs = db.pkg(pkg).unwrap().required_by();

    for pkg in &new_pkgs {
        pkgs.extend(get_required_by_recursive(db, pkg))
    }

    pkgs.extend(new_pkgs);
    pkgs
}

/// Given a package and an `avg::AVG`, returns true if the system is affected
fn system_is_affected(db: alpm::Db, pkg: &str, avg: &Avg) -> bool {
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

/// Given a list of package names, returns true when at least one is installed
fn package_is_installed(db: Db, packages: &[String]) -> bool {
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

/// Merge a list of `avg::AVG` into a single `avg::AVG` using major version as version
fn merge_avgs(cves: &BTreeMap<String, Vec<Avg>>) -> BTreeMap<String, Avg> {
    let mut avgs = BTreeMap::new();
    for (pkg, list) in cves.iter() {
        let avg_fixed = list
            .iter()
            .filter_map(|v| v.fixed.as_ref())
            .max_by_key(|f| Version::new(f.as_str()))
            .map(|s| s.to_string());

        let avg_severity = list.iter().map(|v| v.severity).max().unwrap();
        let avg_status = list.iter().map(|v| v.status).max().unwrap();
        let avg_issues = list.iter().flat_map(|l| l.issues.clone()).collect();
        let avg_types = list.iter().map(|a| a.kind.clone()).collect();

        let avg = Avg {
            issues: avg_issues,
            fixed: avg_fixed,
            severity: avg_severity,
            status: avg_status,
            kind: avg_types,
            ..Avg::default()
        };

        avgs.insert(pkg.clone(), avg);
    }

    avgs
}

fn print_avg(options: &Options, t: &mut term::StdoutTerminal, pkg: &str, avg: &Avg, db: alpm::Db) {
    match avg.fixed {
        Some(ref v) if avg.status != enums::Status::Vulnerable => {
            // Quiet option
            if options.quiet >= 1 {
                write_with_colours(t, pkg, options, Some(avg.severity.to_color()), None);

                if options.quiet == 1 {
                    write!(t, ">=").expect("term::write failed");
                    write_with_colours(t, v, options, Some(term::color::GREEN), None);
                }
            } else {
                match options.format {
                    Some(ref f) => {
                        print_avg_formatted(t, pkg, avg, Some(v), options, db, f);
                    }
                    None => {
                        print_avg_colored(t, pkg, avg, Some(v), options, db);
                    }
                }
            }

            writeln!(t).expect("term::writeln failed");
        }

        _ if !options.upgradable_only => {
            if options.quiet > 0 {
                write_with_colours(t, pkg, options, Some(avg.severity.to_color()), None);
            } else if let Some(ref f) = options.format {
                print_avg_formatted(t, pkg, avg, None, options, db, f);
            } else {
                print_avg_colored(t, pkg, avg, None, options, db);
            }

            writeln!(t).expect("term::writeln failed");
        }
        _ => (),
    }
}

/// Print a list of `avg::AVG`
fn print_avgs(options: &Options, avgs: &BTreeMap<String, Avg>, db: alpm::Db) {
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

    for (pkg, avg) in avgs {
        print_avg(options, t.as_mut(), pkg, avg, db);
    }
}

/// Prints "Package {pkg} is affected by {issues}. {severity}!" colored
fn print_avg_colored(
    t: &mut term::StdoutTerminal,
    pkg: &str,
    avg: &Avg,
    version: Option<&str>,
    options: &Options,
    db: alpm::Db,
) {
    // Bold package
    write!(t, "Package ").expect("term::write failed");
    write_with_colours(t, pkg, options, None, Some(term::Attr::Bold));
    // Normal "is affected by {issues}"
    write!(t, " is affected by {}. ", avg.kind).expect("term::write failed");
    if options.show_cve {
        write!(t, "({}). ", avg.issues.join(",")).expect("term::write failed");
    }

    if options.recursive != 0 {
        let required_by = if options.recursive == 1 {
            get_required_by(db, pkg)
        } else {
            get_required_by_recursive(db, pkg)
        };

        if !required_by.is_empty() {
            write!(t, "It's required by {}. ", required_by.join(", ")).expect("term::write failed");
        }
    }

    // Colored severit
    write_with_colours(
        t,
        &avg.severity.to_string(),
        options,
        Some(avg.severity.to_color()),
        None,
    );
    write!(t, "!").expect("term::write failed");

    if let Some(version) = version {
        if avg.status == enums::Status::Fixed {
            // Print: Update to {}!
            write!(t, " Update to at least ").expect("term::write failed");
            write_with_colours(
                t,
                version,
                options,
                Some(term::color::GREEN),
                Some(term::Attr::Bold),
            );
            write!(t, "!").expect("term::write failed");
        } else if avg.status == enums::Status::Testing && options.show_testing {
            // Print: Update to {} from the testing repos!"
            write!(t, " Update to at least ").expect("term::write failed");
            write_with_colours(
                t,
                version,
                options,
                Some(term::color::GREEN),
                Some(term::Attr::Bold),
            );
            write!(t, " from the testing repos!").expect("term::write failed");
        }
    }
}

/// Prints output formatted as the user wants
fn print_avg_formatted(
    t: &mut term::StdoutTerminal,
    pkg: &str,
    avg: &Avg,
    version: Option<&str>,
    options: &Options,
    db: Db,
    f: &str,
) {
    let mut chars = f.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '%' => match chars.peek() {
                Some('r') => {
                    let required_by = if options.recursive == 1 {
                        get_required_by(db, pkg)
                    } else {
                        get_required_by_recursive(db, pkg)
                    };

                    write!(t, "{}", required_by.join(",").as_str()).expect("term::write failed");
                    chars.next();
                }
                Some('n') => {
                    write_with_colours(t, pkg, options, Some(avg.severity.to_color()), None);
                    chars.next();
                }
                Some('c') => {
                    write!(t, "{}", avg.issues.join(",")).expect("term::write failed");
                    chars.next();
                }
                Some('v') => {
                    if let Some(version) = version {
                        if avg.status == Status::Fixed
                            || (avg.status == Status::Testing && options.show_testing)
                        {
                            write_with_colours(
                                t,
                                version,
                                options,
                                Some(term::color::GREEN),
                                Some(term::Attr::Bold),
                            );
                        }
                    }
                    chars.next();
                }
                Some('t') => {
                    if !avg.kind.is_empty() {
                        write!(t, "{}", avg.kind).expect("term::write failed");
                    }
                    chars.next();
                }
                Some(x) => {
                    debug!("Unknown placeholder {}", x);
                    write!(t, "%").expect("term::write failed");
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
    let show_colors = options.color == enums::Color::Always
        || (t.supports_color() && atty::is(Stream::Stdout) && options.color != enums::Color::Never);

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

    #[test]
    fn test_system_is_affected() {
        let pacman = alpm::Alpm::new(ROOT_DIR, DB_PATH).expect("Alpm::new failed");
        let db = pacman.localdb();

        let avg1 = avg::AVG {
            issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
            fixed: Some("1.0.0".to_string()),
            severity: enums::Severity::Unknown,
            status: enums::Status::Unknown,
            required_by: Vec::new(),
        };

        assert_eq!(false, system_is_affected(&db, &"pacman".to_string(), &avg1));

        let avg2 = avg::AVG {
            issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
            fixed: Some("7.0.0".to_string()),
            severity: enums::Severity::Unknown,
            status: enums::Status::Unknown,
            required_by: Vec::new(),
        };

        assert!(system_is_affected(&db, &"pacman".to_string(), &avg2));
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

    #[test]
    fn test_merge_avgs() {
        let mut avgs: BTreeMap<String, Vec<_>> = BTreeMap::new();

        let avg1 = avg::AVG {
            issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
            fixed: Some("1.0.0".to_string()),
            severity: enums::Severity::Unknown,
            status: enums::Status::Fixed,
            required_by: Vec::new(),
        };

        let avg2 = avg::AVG {
            issues: vec!["CVE-4".to_string(), "CVE-10".to_string()],
            fixed: Some("0.9.8".to_string()),
            severity: enums::Severity::High,
            status: enums::Status::Testing,
            required_by: Vec::new(),
        };

        assert!(enums::Severity::Critical > enums::Severity::High);

        avgs.insert("package".to_string(), vec![avg1.clone(), avg2.clone()]);

        avgs.insert("package2".to_string(), vec![avg1, avg2]);

        let pacman = alpm::Alpm::new(ROOT_DIR, DB_PATH).expect("Alpm::new failed");
        let db = pacman.localdb();

        let merged = merge_avgs(&avgs, &db, &Options::default());

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
}
