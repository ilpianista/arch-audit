use crate::enums::{Severity, Status};
use alpm::{Alpm, Db};
use atty::Stream;
use clap::{load_yaml, App};
use curl::easy::Easy;
use itertools::Itertools;
use log::{debug, info};
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
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
    #[serde(skip)]
    required_by: Vec<String>,
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

    let merged = merge_avgs(&affected_avgs, db, &options);
    print_avgs(&options, &merged);
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

fn get_required_by(db: Db, packages: &[String]) -> Vec<String> {
    packages
        .iter()
        .flat_map(|pkg| db.pkg(pkg.as_str()).unwrap().required_by())
        .collect()
}

/// Given a package and an `avg::AVG`, returns true if the system is affected
fn system_is_affected(db: Db, pkg: &str, avg: &Avg) -> bool {
    match db.pkg(pkg) {
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
fn merge_avgs(
    cves: &BTreeMap<String, Vec<Avg>>,
    db: Db,
    options: &Options,
) -> BTreeMap<String, Avg> {
    let mut avgs: BTreeMap<String, Avg> = BTreeMap::new();
    for (pkg, list) in cves.iter() {
        let mut avg_issues = vec![];
        let mut avg_fixed: Option<String> = None;
        let mut avg_severity = enums::Severity::Unknown;
        let mut avg_status = enums::Status::Unknown;
        let mut avg_types: HashSet<String> = HashSet::new();

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
            avg_types.insert(a.kind.clone());
        }

        let mut avg = Avg {
            issues: avg_issues,
            fixed: avg_fixed,
            severity: avg_severity,
            status: avg_status,
            required_by: Vec::new(),
            kind: avg_types.into_iter().join(", "),
            packages: Vec::new(),
        };

        if options.recursive >= 1 {
            let mut packages = get_required_by(db, &[pkg.clone()]);
            avg.required_by.append(&mut packages.clone());

            loop {
                if !packages.is_empty() && options.recursive > 1 {
                    packages = get_required_by(db, &packages);
                    avg.required_by.append(&mut packages.clone());
                } else {
                    break;
                }
            }
        }

        avgs.insert(pkg.to_string(), avg);
    }

    avgs
}

/// Print a list of `avg::AVG`
fn print_avgs(options: &Options, avgs: &BTreeMap<String, Avg>) {
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
        match avg.fixed {
            Some(ref v) if avg.status != enums::Status::Vulnerable => {
                // Quiet option
                if options.quiet >= 1 {
                    write_with_colours(&mut *t, pkg, options, Some(avg.severity.to_color()), None);

                    if options.quiet == 1 {
                        write!(t, ">=").expect("term::write failed");
                        write_with_colours(&mut *t, v, options, Some(term::color::GREEN), None);
                    }
                } else {
                    match options.format {
                        Some(ref f) => {
                            print_avg_formatted(&mut *t, pkg, avg, v, options, f);
                        }
                        None => {
                            print_avg_colored(&mut *t, pkg, avg, v, options);
                        }
                    }
                }

                writeln!(t).expect("term::writeln failed");
            }
            _ => {
                if !options.upgradable_only {
                    if options.quiet > 0 {
                        write_with_colours(
                            &mut *t,
                            pkg,
                            options,
                            Some(avg.severity.to_color()),
                            None,
                        );
                    } else {
                        match options.format {
                            Some(ref f) => {
                                print_avg_formatted(&mut *t, pkg, avg, "", options, f);
                            }
                            None => {
                                print_avg_colored(&mut *t, pkg, avg, "", options);
                            }
                        }
                    }

                    writeln!(t).expect("term::writeln failed");
                }
            }
        }
    }
}

/// Prints "Package {pkg} is affected by {issues}. {severity}!" colored
fn print_avg_colored(
    t: &mut term::StdoutTerminal,
    pkg: &str,
    avg: &Avg,
    version: &str,
    options: &Options,
) {
    // Bold package
    write!(t, "Package ").expect("term::write failed");
    write_with_colours(t, pkg, options, None, Some(term::Attr::Bold));
    // Normal "is affected by {issues}"
    write!(t, " is affected by {}. ", avg.kind).expect("term::write failed");
    if options.show_cve {
        write!(t, "({}). ", avg.issues.join(",")).expect("term::write failed");
    }

    if !avg.required_by.is_empty() {
        write!(t, "It's required by {}. ", avg.required_by.join(", ")).expect("term::write failed");
    }

    // Colored severit
    write_with_colours(
        t,
        avg.severity.to_string().as_str(),
        options,
        Some(avg.severity.to_color()),
        None,
    );
    write!(t, "!").expect("term::write failed");

    if !version.is_empty() {
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
    version: &str,
    options: &Options,
    f: &str,
) {
    let mut chars = f.chars().peekable();

    loop {
        match chars.next() {
            Some('%') => match chars.peek() {
                Some('r') => {
                    write!(t, "{}", avg.required_by.iter().join(",").as_str())
                        .expect("term::write failed");
                    chars.next();
                }
                Some('n') => {
                    write_with_colours(t, pkg, options, Some(avg.severity.to_color()), None);
                    chars.next();
                }
                Some('c') => {
                    write!(t, "{}", avg.issues.iter().join(",").as_str())
                        .expect("term::write failed");
                    chars.next();
                }
                Some('v') => {
                    if !version.is_empty()
                        && (avg.status == Status::Fixed
                            || (avg.status == Status::Testing && options.show_testing))
                    {
                        write_with_colours(
                            t,
                            version,
                            options,
                            Some(term::color::GREEN),
                            Some(term::Attr::Bold),
                        );
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
            Some(x) => {
                write!(t, "{}", x).expect("term::write failed");
            }
            None => break,
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
