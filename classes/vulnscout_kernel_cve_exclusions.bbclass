VULNSCOUT_CVE_EXCLUSIONS_WORKDIR ?= "${WORKDIR}/cvelistV5"
VULNSCOUT_CVELISTV5_PATH ?= "${VULNSCOUT_CVE_EXCLUSIONS_WORKDIR}/git"

python do_clone_cvelistV5() {
    import subprocess
    import shutil, os
    rootdir = d.getVar("VULNSCOUT_CVELISTV5_PATH")
    d.setVar("SRC_URI", "git://github.com/CVEProject/cvelistV5.git;branch=main;protocol=https")
    d.setVar("SRCREV", "${AUTOREV}")
    src_uri = (d.getVar('SRC_URI') or "").split()
    # Fetch the kernel vulnerabilities sources
    fetcher = bb.fetch2.Fetch(src_uri, d)
    fetcher.download()
    # Unpack into the standard work directory
    fetcher.unpack(rootdir)
    # Remove the folder ${PN} set by unpack (like core-image-minimal)
    subdirs = [d for d in os.listdir(rootdir) if os.path.isdir(os.path.join(rootdir, d))]
    if len(subdirs) == 1:
        srcdir = os.path.join(rootdir, subdirs[0])
        for f in os.listdir(srcdir):
            shutil.move(os.path.join(srcdir, f), rootdir)
        shutil.rmtree(srcdir)
    bb.note("Vulnerabilities repo unpacked into: %s" % rootdir)
}
do_clone_cvelistV5[network] = "1"
do_clone_cvelistV5[nostamp] = "1"
do_clone_cvelistV5[doc] = "Clone CVE information from the CVE Project: https://github.com/CVEProject/cvelistV5.git"
addtask clone_cvelistV5 after do_fetch before do_generate_cve_exclusions

do_generate_cve_exclusions() {
    generate_cve_exclusions_script=$(find ${COREBASE} -name "generate-cve-exclusions.py")
    if [ -z "${generate_cve_exclusions_script}" ]; then
        bbfatal "generate-cve-exclusions.py not found in ${COREBASE}."
    fi
    python3 "${generate_cve_exclusions_script}" \
        ${VULNSCOUT_CVELISTV5_PATH} \
        ${LINUX_VERSION} > ${VULNSCOUT_CVE_EXCLUSIONS_WORKDIR}/cve-exclusion_${LINUX_VERSION}.inc
}
do_generate_cve_exclusions[nostamp] = "1"
do_generate_cve_exclusions[doc] = "Generate CVE exclusions for the kernel build. (e.g., cve-exclusion_6.12.inc)"
addtask generate_cve_exclusions after do_clone_cvelistV5 before do_cve_check

python do_cve_check:prepend() {
    import os
    import re

    workdir = d.getVar("VULNSCOUT_CVE_EXCLUSIONS_WORKDIR")
    kernel_version = d.getVar("LINUX_VERSION")
    inc_file = os.path.join(workdir, "cve-exclusion_%s.inc" % kernel_version)

    if os.path.exists(inc_file):
        bb.warn("CVE exclusion file found: %s" % inc_file)
        pattern = re.compile(
            r'^\s*CVE_STATUS\[(CVE-\d+-\d+)\]\s*=\s*"(.*?)"\s*(?:#.*)?$'
        )
        count = 0
        with open(inc_file, 'r') as f:
            for line in f:
                m = pattern.match(line)
                if not m:
                    continue

                cve_id, status = m.groups()
                d.setVarFlag("CVE_STATUS", cve_id, status)
                count += 1
        bb.note("Loaded %d CVE_STATUS entries from %s" % (count, inc_file))
}