# arch-audit

[![crats.io](https://img.shields.io/crates/v/arch-audit.svg)](https://crates.io/crates/arch-audit)
[![Build Status](https://travis-ci.org/ilpianista/arch-audit.svg?branch=master)](https://travis-ci.org/ilpianista/arch-audit)
[![Flattr this git repo](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=ilpianista&url=https://github.com/ilpianista/arch-audit&title=arch-audit&language=&tags=archlinux&category=software)

[pkg-audit](https://www.freebsd.org/cgi/man.cgi?query=pkg-audit&sektion=8)-like utility for [Arch Linux](https://archlinux.org).

Uses data collected by the awesome [Arch Security Team](https://wiki.archlinux.org/index.php/Arch_Security_Team).

## Installation

### Latest release from official repositories

    pacman -S arch-audit

### Development version from AUR

The PKGBUILD is available [on AUR](https://aur.archlinux.org/packages/arch-audit-git).

After the installation just execute `arch-audit`.

### Development version from sources

    git clone https://github.com/ilpianista/arch-audit
    cd arch-audit
    cargo build
    cargo run

## Example output

    $ arch-audit
    Package bzip2 is affected by CVE-2016-3189. Medium risk!
    Package curl is affected by CVE-2016-9594, CVE-2016-9586. Update to 7.52.1-1!
    Package gst-plugins-bad is affected by CVE-2016-9447, CVE-2016-9446, CVE-2016-9445. High risk!
    Package jasper is affected by CVE-2016-8886. Medium risk!
    Package libimobiledevice is affected by CVE-2016-5104. Low risk!
    Package libtiff is affected by CVE-2015-7554. Critical risk!
    Package libusbmuxd is affected by CVE-2016-5104. Low risk!
    Package openjpeg2 is affected by CVE-2016-9118, CVE-2016-9117, CVE-2016-9116, CVE-2016-9115, CVE-2016-9114, CVE-2016-9113. High risk!
    Package openssl is affected by CVE-2016-7055. Low risk!

    $ arch-audit --upgradable --quiet
    curl>=7.52.1-1

    $ arch-audit -uf "%n|%c"
    curl|CVE-2016-9594,CVE-2016-9586

## Donate

Donations via either [PayPal](https://www.paypal.me/andreascarpino) or Bitcoin (1Ph3hFEoQaD4PK6MhL3kBNNh9FZFBfisEH) are always welcomed, thank you!

## False Positive

**Please** before reporting false positive check https://security.archlinux.org first. `arch-audit` parses that page and then if that page reports a false positive, `arch-audit` will do too. Get in touch with the Arch Linux Security team via IRC at freenode#archlinux-security. Thanks!

## License

MIT
