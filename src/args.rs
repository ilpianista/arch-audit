use std::io::stdout;
use std::path::PathBuf;

use structopt::clap::{AppSettings, Shell};
use structopt::StructOpt;

use anyhow::Result;
use lazy_static::lazy_static;
use strum::VariantNames;
use strum_macros::{EnumString, EnumVariantNames, ToString};

#[derive(Debug, StructOpt)]
#[structopt(about="A utility like pkg-audit for Arch Linux.", global_settings = &[AppSettings::ColoredHelp, AppSettings::DeriveDisplayOrder])]
pub struct Args {
    /// Show only vulnerable package names and their versions. Set twice to hide the versions as well.
    #[structopt(long, short = "q", parse(from_occurrences))]
    pub quiet: u8,
    /// Prints packages that depend on vulnerable packages and are thus potentially vulnerable as well. Set twice to show ALL the packages that requires them.
    #[structopt(long, short = "r", parse(from_occurrences))]
    pub recursive: u8,
    /// Show packages which are in the [testing] repos. See https://wiki.archlinux.org/index.php/Official_repositories#Testing_repositories
    #[structopt(long = "show-testing", short = "t")]
    pub testing: bool,
    /// Show only packages that have already been fixed
    #[structopt(long, short = "u", long)]
    pub upgradable: bool,
    /// Bypass tty detection for colors
    #[structopt(long, short = "C", default_value = "auto", possible_values=&Color::VARIANTS)]
    pub color: Color,
    /// Set an alternate database location
    #[structopt(
        long,
        short = "b",
        parse(from_os_str),
        default_value = "/var/lib/pacman"
    )]
    pub dbpath: PathBuf,
    /// Specify a format to control the output. Placeholders are %n (pkgname), %c (CVEs), %v (fixed version), %t (type), %s (severity), and %r (required by, only when -r is also used).
    #[structopt(long, short = "f")]
    pub format: Option<String>,
    /// Specify the URL or file path to the security tracker json data
    #[structopt(long)]
    pub source: Option<String>,
    /// Send requests through a proxy
    #[structopt(long)]
    pub proxy: Option<String>,
    /// Do not use a proxy even if one is configured
    #[structopt(long)]
    pub no_proxy: bool,
    /// Specify how to sort the output
    #[structopt(long, use_delimiter = true, possible_values = &SortBy::VARIANTS, default_value = &SORT_BY_DEFAULT_VALUE)]
    pub sort: Vec<SortBy>,
    /// Print the CVE numbers.
    #[structopt(long, short = "c")]
    pub show_cve: bool,
    #[structopt(subcommand)]
    pub subcommand: Option<SubCommand>,
}

#[derive(Debug, StructOpt)]
pub enum SubCommand {
    /// Generate shell completions
    #[structopt(name = "completions")]
    Completions(Completions),
}

#[derive(Debug, StructOpt, ToString, EnumString, EnumVariantNames)]
#[strum(serialize_all = "lowercase")]
pub enum Color {
    Auto,
    Always,
    Never,
}

impl Default for Color {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, StructOpt, ToString, EnumString, EnumVariantNames)]
#[strum(serialize_all = "snake_case")]
pub enum SortBy {
    Severity,
    Pkgname,
    Upgradable,
    Reverse,
}

lazy_static! {
    static ref SORT_BY_DEFAULT_VALUE: String = vec![SortBy::Severity, SortBy::Pkgname,]
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<String>>()
        .join(",");
}

#[derive(Debug, StructOpt)]
pub struct Completions {
    #[structopt(possible_values=&Shell::variants())]
    pub shell: Shell,
}

pub fn gen_completions(args: &Completions) -> Result<()> {
    Args::clap().gen_completions_to("dfrs", args.shell, &mut stdout());
    Ok(())
}
