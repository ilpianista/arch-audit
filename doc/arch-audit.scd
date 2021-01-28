arch-audit(1)

# NAME

arch-audit - A utility like pkg-audit for Arch Linux.

# SYNOPSIS

*arch-audit* [_OPTION_]...

# DESCRIPTION

A utility like pkg-audit for Arch Linux.++
Based on data from https://security.archlinux.org collected by the awesome Arch Security Team.

# OPTIONS

*-q*, *--quiet*
	Show only vulnerable package names and their versions. Set twice to hide the versions as well

*-r*, *--recursive*
	Prints packages that depend on vulnerable packages and are thus potentially vulnerable as well.++
Set twice to show ALL the packages that requires them

*-t*, *--show-testing*
	Show packages which are in the [testing] repos.++
See https://wiki.archlinux.org/index.php/Official_repositories#Testing_repositories

*-u*, *--upgradable*
	Show only packages that have already been fixed

*-c*, *--show-cve*
	Print the CVE numbers

*-C*, *--color* [_WHEN_]
	Colorize the output; _WHEN_ can be 'auto' (default if omitted), 'always', or 'never'

*-b*, *--dbpath* [_DBPATH_]
	Set an alternate database location. By default, arch-audit uses /var/lib/pacman

*-f*, *--format* [_FORMAT_]
	Specify a format to control the output. Placeholders are:

	%n	pkgname

	%c	CVEs

	%v	fixed version

	%t	type

	%s	severity

	%r	required by (only when -r is also used)

*-V*, *--version*
	Prints version information

*-h*, *--help*
	Prints help information

# INFOS
	Read more at _https://wiki.archlinux.org/index.php/Arch_Security_Team_

# BUGS
	Bugs can be reported on the bug tracker _https://gitlab.com/ilpianista/arch-audit/-/issues_

# AUTHORS
	Andrea Scarpino <andrea@archlinux.org>
