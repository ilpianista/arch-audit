use crate::args::SortBy;
use crate::Affected;

use std::cmp;

pub fn cmp_by_severity(a: &&Affected, b: &&Affected) -> cmp::Ordering {
    (a.severity as u64).cmp(&(b.severity as u64)).reverse()
}

pub fn cmp_by_pkgname(a: &&Affected, b: &&Affected) -> cmp::Ordering {
    a.package.cmp(&b.package)
}

pub fn cmp_by_upgradable(a: &&Affected, b: &&Affected) -> cmp::Ordering {
    a.fixed.is_some().cmp(&b.fixed.is_some())
}

pub fn sort_affected(affected: &mut Vec<&Affected>, sort_by: &[SortBy]) {
    for sort in sort_by.iter().rev() {
        match sort {
            SortBy::Severity => affected.sort_by(cmp_by_severity),
            SortBy::Pkgname => affected.sort_by(cmp_by_pkgname),
            SortBy::Upgradable => affected.sort_by(cmp_by_upgradable),
            SortBy::Reverse => affected.reverse(),
        }
    }
}
