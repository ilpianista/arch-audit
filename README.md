# arch-audit

[![crats.io](https://img.shields.io/crates/v/arch-audit.svg)](https://crates.io/crates/arch-audit)
[![Build Status](https://travis-ci.org/ilpianista/arch-audit.svg?branch=master)](https://travis-ci.org/ilpianista/arch-audit)
[![Flattr this git repo](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=ilpianista&url=https://github.com/ilpianista/arch-audit&title=arch-audit&language=&tags=archlinux&category=software)

[pkg-audit](https://www.freebsd.org/cgi/man.cgi?query=pkg-audit&sektion=8)-like utility for [Arch Linux](https://archlinux.org).

Uses data collected by the awesome [Arch CVE Monitoring Team](https://wiki.archlinux.org/index.php/Arch_CVE_Monitoring_Team).

**This is WIP.**

## Installation

### From AUR

The PKGBUILD is available [on AUR](https://aur.archlinux.org/packages/arch-audit).

After the installation just execute `arch-audit`.

### From sources

    git clone https://github.com/ilpianista/arch-audit
    cd arch-audit
    cargo build
    cargo run

## Example output

    $ arch-audit
    Package libwmf is affected by ["CVE-2009-1364", "CVE-2006-3376", "CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3477", "CVE-2009-3546", "CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696"]. VULNERABLE!
    Package libtiff is affected by ["CVE-2016-5875", "CVE-2016-5314", "CVE-2016-5315", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5321", "CVE-2016-5322", "CVE-2016-5323", "CVE-2016-5102", "CVE-2016-3991", "CVE-2016-3990", "CVE-2016-3945", "CVE-2016-3658", "CVE-2016-3634", "CVE-2016-3633", "CVE-2016-3632", "CVE-2016-3631", "CVE-2016-3625", "CVE-2016-3624", "CVE-2016-3623", "CVE-2016-3622", "CVE-2016-3621", "CVE-2016-3620", "CVE-2016-3619", "CVE-2016-3186", "CVE-2015-8668", "CVE-2015-7313", "CVE-2014-8130", "CVE-2014-8127", "CVE-2010-2596", "CVE-2016-6223"]. VULNERABLE!
    Package libtiff is affected by ["CVE-2015-7554", "CVE-2015-8683"]. VULNERABLE!
    Package jasper is affected by ["CVE-2015-8751"]. VULNERABLE!
    Package jasper is affected by ["CVE-2015-5221"]. VULNERABLE!
    Package jasper is affected by ["CVE-2015-5203"]. VULNERABLE!
    Package lib32-openssl is affected by ["CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306"]. Update to 1:1.0.2.i-1!
    Package wireshark-cli is affected by ["CVE-2016-7180", "CVE-2016-7175", "CVE-2016-7176", "CVE-2016-7177", "CVE-2016-7178", "CVE-2016-7179"]. Update to 2.2.0-1!
    Package wpa_supplicant is affected by ["CVE-2016-4477", "CVE-2016-4476"]. VULNERABLE!
    Package openssl is affected by ["CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306"]. Update to 1.0.2.i-1!
    Package crypto++ is affected by ["CVE-2016-7420"]. VULNERABLE!
    Package bzip2 is affected by ["CVE-2016-3189"]. VULNERABLE!
    Package libimobiledevice is affected by ["CVE-2016-5104"]. VULNERABLE!
    Package libusbmuxd is affected by ["CVE-2016-5104"]. VULNERABLE!
    Package gdk-pixbuf2 is affected by ["CVE-2016-6352"]. VULNERABLE!

    $ arch-audit --upgradable --quiet
    wireshark-cli>=2.2.0-1
    openssl>=1.0.2.i-1
    lib32-openssl>=1:1.0.2.i-1

    $ arch-audit -uf "%n|%c"
    openssl|CVE-2016-2177,CVE-2016-2178,CVE-2016-2179,CVE-2016-2180,CVE-2016-2181,CVE-2016-2182,CVE-2016-2183,CVE-2016-6302,CVE-2016-6303,CVE-2016-6304,CVE-2016-6306
    wireshark-cli|CVE-2016-7180,CVE-2016-7175,CVE-2016-7176,CVE-2016-7177,CVE-2016-7178,CVE-2016-7179
    lib32-openssl|CVE-2016-2177,CVE-2016-2178,CVE-2016-2179,CVE-2016-2180,CVE-2016-2181,CVE-2016-2182,CVE-2016-2183,CVE-2016-6302,CVE-2016-6303,CVE-2016-6304,CVE-2016-6306

