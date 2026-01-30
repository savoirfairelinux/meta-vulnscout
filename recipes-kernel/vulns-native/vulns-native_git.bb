SUMMARY = "Linux Security Vulns Repo"
DESCRIPTION = "Repo for tracking and maintaining the CVE identifiers reserved and assigned to \
the Linux kernel project."
HOMEPAGE = "https://git.kernel.org/pub/scm/linux/security/vulns.git/"
LICENSE = "cve-tou"
LIC_FILES_CHKSUM = "file://LICENSES/cve-tou.txt;md5=0d1f8ff7666c210e0b0404fd9d7e6703"

inherit native allarch

SRC_URI = "git://git.kernel.org/pub/scm/linux/security/vulns.git;branch=master;protocol=https"
VULNS_USE_AUTOREV ?= "0"
VULNS_DEFAULT_SRCREV ?= "2c9b20d7a0699222b58c4824560b716b6096637b"

python __anonymous () {
    if d.getVar("VULNS_USE_AUTOREV") == "1":
        d.setVar("SRCREV", d.getVar("AUTOREV"))
    else:
        d.setVar("SRCREV", d.getVar("VULNS_DEFAULT_SRCREV"))
}

do_install(){
	install -d ${D}${datadir}/vulns-native
	cp -r ${UNPACKDIR}/vulns-git/* ${D}${datadir}/vulns-native/
}
