#![deny(clippy::nursery, clippy::cargo)]
extern crate strum;
extern crate strum_macros;

use args::*;
mod args;

use types::*;
mod types;

use util::*;
mod util;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::process::exit;
use std::str;

use alpm::{Alpm, Db, Version};
use anyhow::{Context, Result};
use atty::Stream;
use curl::easy::Easy;
use log::{debug, info};
use std::fs::read_to_string;
use structopt::StructOpt;
use term::terminfo::TermInfo;
use term::{color, Attr};
use term::{StdoutTerminal, TerminfoTerminal};
use url::Url;

fn main() {
    let args = Args::from_args();

    env_logger::init();

    if let Err(err) = run(args) {
        eprintln!("Error: {}", err);
        for cause in err.chain().skip(1) {
            eprintln!("Because: {}", cause);
        }
        exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    if let Some(SubCommand::Completions(completions)) = args.subcommand {
        args::gen_completions(&completions)?;
        return Ok(());
    }

    let avgs = get_avg_json(args.source.as_str()).context("failed to get AVG json")?;
    let avgs: Avgs = serde_json::from_str(&avgs).context("failed to parse json")?;

    let dbpath = args
        .dbpath
        .to_str()
        .context("failed to convert dbpath to str")?;
    let pacman = Alpm::new("/", dbpath)
        .with_context(|| format!("failed to initial alpm: root='/' dbpath='{}'", dbpath))?;
    let db = pacman.localdb();

    let mut affected = BTreeMap::new();

    for avg in &avgs.avgs {
        if avg.status == Status::NotAffected {
            continue;
        }

        for pkg in &avg.packages {
            if !system_is_affected(db, pkg, avg) {
                continue;
            }
            if !is_status_shown(avg.status, &args) {
                continue;
            }

            let aff = affected
                .entry(pkg.as_str())
                .or_insert_with(|| Affected::new(pkg));
            aff.severity = aff.severity.max(avg.severity);
            aff.cves.extend(avg.issues.clone());
            aff.kind.push(avg.kind.clone());
            aff.status = avg.status;
            if aff.fixed.as_ref().map(|f| Version::new(f.as_str()))
                < avg.fixed.as_ref().map(|f| Version::new(f.as_str()))
            {
                aff.fixed = avg.fixed.clone();
            }

            aff.kind.dedup()
        }
    }

    print_all_affected(&args, &affected, db)?;
    Ok(())
}

fn get_avg_json(from: &str) -> Result<String> {
    let json = match Url::parse(from) {
        Ok(url) => fetch_avg_json(&url).context("failed to fetch AVGs from URL")?,
        Err(_) => read_to_string(from).context("failed to read AVGs from file")?,
    };
    Ok(json)
}

fn fetch_avg_json(url: &Url) -> Result<String> {
    let mut avgs = Vec::new();
    info!("Downloading AVGs from {}", url);

    let mut easy = Easy::new();
    easy.fail_on_error(true)?;
    easy.follow_location(true)?;
    easy.url(url.as_str())?;
    let mut transfer = easy.transfer();
    transfer.write_function(|data| {
        avgs.extend(data);
        Ok(data.len())
    })?;
    transfer.perform()?;
    drop(transfer);

    let json = String::from_utf8(avgs).context("failed to decode utf8")?;
    Ok(json)
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

/// Given a `Status` return if it should be shown based on the status and passed `Options`
const fn is_status_shown(status: Status, options: &Args) -> bool {
    match status {
        Status::Unknown => !options.upgradable,
        Status::NotAffected => false,
        Status::Vulnerable => !options.upgradable,
        Status::Fixed => true,
        Status::Testing => options.testing,
    }
}

/// Print a single Affected
fn print_affected(
    options: &Args,
    t: &mut term::StdoutTerminal,
    aff: &Affected,
    db: Db,
) -> Result<()> {
    match aff.fixed {
        Some(ref v) => {
            // Quiet option
            if options.quiet >= 1 {
                write_with_colours(
                    t,
                    &aff.package,
                    options,
                    Some(aff.severity.to_color()),
                    None,
                )?;

                if options.quiet == 1 {
                    write!(t, ">=")?;
                    write_with_colours(t, v, options, Some(term::color::GREEN), None)?;
                }
            } else {
                match options.format {
                    Some(ref f) => {
                        print_affected_formatted(t, aff, options, f, db)?;
                    }
                    None => {
                        print_affected_colored(t, aff, options, db)?;
                    }
                }
            }

            writeln!(t)?;
        }

        _ if !options.upgradable => {
            if options.quiet > 0 {
                write_with_colours(
                    t,
                    &aff.package,
                    options,
                    Some(aff.severity.to_color()),
                    None,
                )?;
            } else if let Some(ref f) = options.format {
                print_affected_formatted(t, aff, options, f, db)?;
            } else {
                print_affected_colored(t, aff, options, db)?;
            }

            writeln!(t)?;
        }
        _ => (),
    }
    Ok(())
}

// Print a list of Affected
fn print_all_affected(options: &Args, affected: &BTreeMap<&str, Affected>, db: Db) -> Result<()> {
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

    let mut affected = affected.values().into_iter().collect::<Vec<&Affected>>();
    sort_affected(&mut affected, &options.sort);

    for aff in affected {
        print_affected(options, t.as_mut(), aff, db)?;
    }

    Ok(())
}

/// Prints "{pkg} is affected by {issues}. {severity}!" colored
fn print_affected_colored(
    t: &mut term::StdoutTerminal,
    aff: &Affected,
    options: &Args,
    db: Db,
) -> Result<()> {
    // Bold package
    write_with_colours(t, &aff.package, options, None, Some(term::Attr::Bold))?;
    // Normal "is affected by {issues}"
    write!(t, " is affected by {}. ", aff.kind.join(", "))?;
    if options.show_cve {
        write!(t, "({}). ", aff.cves.join(", "))?;
    }

    if options.recursive != 0 {
        let required_by = if options.recursive == 1 {
            get_required_by(db, &aff.package)
        } else {
            get_required_by_recursive(db, &aff.package)
        };

        if !required_by.is_empty() {
            write!(t, "It's required by {}. ", required_by.join(", "))?;
        }
    }

    // Colored severit
    write_with_colours(
        t,
        &aff.severity.to_string(),
        options,
        Some(aff.severity.to_color()),
        None,
    )?;
    write!(t, "!")?;

    if let Some(ref version) = aff.fixed {
        if aff.status == Status::Fixed {
            // Print: Update to {}!
            write!(t, " Update to at least ")?;
            write_with_colours(t, version, options, Some(color::GREEN), Some(Attr::Bold))?;
            write!(t, "!")?;
        } else if aff.status == Status::Testing && options.testing {
            // Print: Update to {} from the testing repos!"
            write!(t, " Update to at least")?;
            write_with_colours(t, version, options, Some(color::GREEN), Some(Attr::Bold))?;
            write!(t, " from the testing repos!")?;
        }
    }
    Ok(())
}

/// Prints output formatted as the user wants
fn print_affected_formatted(
    t: &mut term::StdoutTerminal,
    aff: &Affected,
    options: &Args,
    f: &str,
    db: Db,
) -> Result<()> {
    let mut chars = f.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '%' => match chars.peek() {
                Some('%') => {
                    write!(t, "%")?;
                    chars.next();
                }
                Some('r') => {
                    write!(
                        t,
                        "{}",
                        get_required_by(db, &aff.package).join(",").as_str()
                    )?;
                    chars.next();
                }
                Some('n') => {
                    write_with_colours(
                        t,
                        &aff.package,
                        options,
                        Some(aff.severity.to_color()),
                        None,
                    )?;
                    chars.next();
                }
                Some('c') => {
                    write!(t, "{}", aff.cves.join(", "))?;
                    chars.next();
                }
                Some('v') => {
                    if let Some(ref version) = aff.fixed {
                        if aff.status == Status::Fixed
                            || (aff.status == Status::Testing && options.testing)
                        {
                            write_with_colours(
                                t,
                                version,
                                options,
                                Some(color::GREEN),
                                Some(Attr::Bold),
                            )?;
                        }
                    }
                    chars.next();
                }
                Some('s') => {
                    write_with_colours(
                        t,
                        &aff.severity.to_string(),
                        options,
                        Some(aff.severity.to_color()),
                        None,
                    )?;
                    chars.next();
                }
                Some('t') => {
                    if !aff.kind.is_empty() {
                        write!(t, "{}", aff.kind.join(", "))?;
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
                write!(t, "{}", x)?;
            }
        }
    }
    Ok(())
}

fn write_with_colours(
    t: &mut term::StdoutTerminal,
    text: &str,
    options: &Args,
    color: Option<term::color::Color>,
    attribute: Option<term::Attr>,
) -> Result<()> {
    let show_colors = match options.color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => t.supports_color() && atty::is(Stream::Stdout),
    };

    if show_colors {
        if let Some(c) = color {
            t.fg(c)?;
        }
        if let Some(a) = attribute {
            t.attr(a)?;
        }
    }

    write!(t, "{}", text)?;

    if show_colors {
        t.reset()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{types, Args};
    use alpm::Alpm;
    use anyhow::{Context, Result};
    use std::fs::{create_dir, File};
    use std::io::Write;
    use tempfile::Builder as TempfileBuilder;
    use tempfile::TempDir;

    struct Fixture;

    impl Fixture {
        fn alpm(packages: Vec<&str>) -> Result<(TempDir, Alpm)> {
            let tempdir = TempfileBuilder::new()
                .prefix("arch-audit-test-")
                .tempdir()?;

            let local_path = tempdir.path().join("local");
            create_dir(local_path.clone())?;

            let alpm_db_version_path = local_path.join("ALPM_DB_VERSION");
            let mut alpm_db_version_path = File::create(alpm_db_version_path)?;
            writeln!(alpm_db_version_path, "9")?;

            for package in packages {
                let file_path = local_path.join(package);
                create_dir(file_path)?;
            }

            let path = tempdir
                .path()
                .to_str()
                .context("Failed to convert tempdir path to str")?;
            let alpm = Alpm::new(path, path)?;
            Ok((tempdir, alpm))
        }

        fn options(upgradable: bool, testing: bool) -> Args {
            Args {
                color: Color::Never,
                dbpath: Default::default(),
                format: None,
                quiet: 0,
                recursive: 0,
                upgradable,
                testing,
                show_cve: false,
                sort: vec![],
                source: "".to_string(),
                subcommand: None,
            }
        }
    }

    #[test]
    fn test_system_is_affected() -> Result<()> {
        let (_tempdir, alpm) = Fixture::alpm(vec!["filesystem-2000.0.0-1"])?;
        let db = alpm.localdb();

        let avg = Avg {
            issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
            fixed: Some("3009.0.0".to_string()),
            severity: types::Severity::Unknown,
            status: types::Status::Unknown,
            packages: Vec::new(),
            kind: String::new(),
        };

        assert!(system_is_affected(db, "filesystem", &avg));
        Ok(())
    }

    #[test]
    fn test_system_is_affected_already_fixed() -> Result<()> {
        let (_tempdir, alpm) = Fixture::alpm(vec!["filesystem-2000.0.0-1"])?;
        let db = alpm.localdb();

        let avg = Avg {
            issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
            fixed: Some("2000.0.0-1".to_string()),
            severity: types::Severity::Unknown,
            status: types::Status::Unknown,
            packages: Vec::new(),
            kind: String::new(),
        };

        assert_eq!(false, system_is_affected(db, "filesystem", &avg));
        Ok(())
    }

    #[test]
    fn test_system_is_affected_package_not_instaled() -> Result<()> {
        let (_tempdir, alpm) = Fixture::alpm(vec![])?;
        let db = alpm.localdb();

        let avg = Avg {
            issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
            fixed: Some("3000.0.0".to_string()),
            severity: types::Severity::Unknown,
            status: types::Status::Unknown,
            packages: Vec::new(),
            kind: String::new(),
        };

        assert_eq!(false, system_is_affected(db, "doesnotexit", &avg));
        Ok(())
    }

    #[test]
    fn test_system_is_affected_same_version_installed() -> Result<()> {
        let (_tempdir, alpm) = Fixture::alpm(vec!["filesystem-2021.01.19-1"])?;
        let db = alpm.localdb();

        let avg = Avg {
            issues: vec!["CVE-1".to_string(), "CVE-2".to_string()],
            fixed: Some("2021.01.19-1".to_string()),
            severity: types::Severity::Unknown,
            status: types::Status::Unknown,
            packages: Vec::new(),
            kind: String::new(),
        };

        assert_eq!(false, system_is_affected(db, "doesnotexit", &avg));
        Ok(())
    }

    #[test]
    fn test_is_status_shown_unknown() {
        assert!(is_status_shown(
            Status::Unknown,
            &Fixture::options(false, false)
        ));
        assert!(is_status_shown(
            Status::Unknown,
            &Fixture::options(false, true)
        ));
    }

    #[test]
    fn test_is_status_shown_unknown_upgradable_only() {
        assert_eq!(
            false,
            is_status_shown(Status::Unknown, &Fixture::options(true, false))
        );
        assert_eq!(
            false,
            is_status_shown(Status::Unknown, &Fixture::options(true, true))
        );
    }

    #[test]
    fn test_is_status_shown_not_affected() {
        assert_eq!(
            false,
            is_status_shown(Status::NotAffected, &Fixture::options(false, false))
        );
        assert_eq!(
            false,
            is_status_shown(Status::NotAffected, &Fixture::options(false, true))
        );
        assert_eq!(
            false,
            is_status_shown(Status::NotAffected, &Fixture::options(true, false))
        );
        assert_eq!(
            false,
            is_status_shown(Status::NotAffected, &Fixture::options(true, true))
        );
    }

    #[test]
    fn test_is_status_shown_vulnerable() {
        assert!(is_status_shown(
            Status::Vulnerable,
            &Fixture::options(false, false)
        ));
        assert!(is_status_shown(
            Status::Vulnerable,
            &Fixture::options(false, true)
        ));
    }

    #[test]
    fn test_is_status_shown_vulnerable_upgradable_only() {
        assert_eq!(
            false,
            is_status_shown(Status::Vulnerable, &Fixture::options(true, false))
        );
        assert_eq!(
            false,
            is_status_shown(Status::Vulnerable, &Fixture::options(true, true))
        );
    }

    #[test]
    fn test_is_status_shown_fixed() {
        assert!(is_status_shown(
            Status::Fixed,
            &Fixture::options(false, false)
        ));
        assert!(is_status_shown(
            Status::Fixed,
            &Fixture::options(false, true)
        ));
        assert!(is_status_shown(
            Status::Fixed,
            &Fixture::options(true, false)
        ));
        assert!(is_status_shown(
            Status::Fixed,
            &Fixture::options(true, true)
        ));
    }

    #[test]
    fn test_is_status_shown_no_testing() {
        assert_eq!(
            false,
            is_status_shown(Status::Testing, &Fixture::options(false, false))
        );
        assert_eq!(
            false,
            is_status_shown(Status::Testing, &Fixture::options(true, false))
        );
    }

    #[test]
    fn test_is_status_shown_testing() {
        assert!(is_status_shown(
            Status::Testing,
            &Fixture::options(false, true)
        ));
        assert!(is_status_shown(
            Status::Testing,
            &Fixture::options(true, true)
        ));
    }
}
