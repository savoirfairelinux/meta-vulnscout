# Enable or disable the kernel CVE improve feature
VULNSCOUT_KERNEL_IMPROVE_CVE ?= "true"

python do_clean:append() {
    import os, glob

    if d.getVar('VULNSCOUT_KERNEL_IMPROVE_CVE') == "true" and bb.utils.contains('INHERIT', 'create-spdx-2.2', 'false', 'true', d):
        deploy_dir = d.expand('${DEPLOY_DIR_IMAGE}')
        for f in glob.glob(os.path.join(deploy_dir, '*scouted.json')):
            bb.note("Removing " + f)
            os.remove(f)
}

python do_clone_kernel_cve() {
    import subprocess
    import shutil, os
    kernel_improve_cve = d.getVar("VULNSCOUT_KERNEL_IMPROVE_CVE")
    check_spdx = d.getVar("INHERIT")
    rootdir = os.path.join(d.getVar("WORKDIR"), "vulns")

    # Check if the feature is enabled and if SPDX 2.2 is not used
    if kernel_improve_cve == "true" and "create-spdx-2.2" not in check_spdx:
        # Delete previous folder for fetching update
        subprocess.run(['rm', '-rf', rootdir])
        d.setVar("SRC_URI", "git://git.kernel.org/pub/scm/linux/security/vulns.git;branch=master;protocol=https")
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
    elif kernel_improve_cve == "false":
        bb.warn(f"Vulnscout: Extra Kernel CVEs Scouting is desactivate because VULNSCOUT_KERNEL_IMPROVE_CVE is set to false.")
    elif "create-spdx-2.2" in check_spdx:
        bb.warn(f"Vulnscout: Extra Kernel CVEs Scouting is desactivate because incompatible with SPDX 2.2.")
}

do_clone_kernel_cve[network] = "1"
do_clone_kernel_cve[nostamp] = "1"
do_clone_kernel_cve[doc] = "Clone the latest kernel vulnerabilities from https://git.kernel.org/pub/scm/linux/security/vulns.git"
addtask clone_kernel_cve after do_fetch before do_setup_vulnscout

do_scout_extra_kernel_vulns() {
    spdx_file="${SPDXIMAGEDEPLOYDIR}/${IMAGE_LINK_NAME}.spdx.json"
    original_cve_check_file="${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json"
    new_cve_report_file="${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.scouted.json"
    docker_compose_file="${VULNSCOUT_DEPLOY_DIR}/docker-compose.yml"
    improve_kernel_cve_script=$(find ${VULNSCOUT_ROOT_DIR} -name "improve_kernel_cve_report.py")

    if [ "${VULNSCOUT_KERNEL_IMPROVE_CVE}" != "true" ]; then
        bbwarn "Vulnscout: Skipping extra kernel vulnerabilities scouting (VULNSCOUT_KERNEL_IMPROVE_CVE set to false)"
        return 0
    elif ${@bb.utils.contains('INHERIT', 'create-spdx-2.2', 'true', 'false', d)}; then
        bbwarn "Vulnscout: Skipping extra kernel vulnerabilities scouting because incompatible with SPDX 2."
        return 0
    elif [ ! -f "${spdx_file}" ]; then
        bbwarn "Vulnscout: SPDX file not found: ${spdx_file}. Skipping extra kernel vulnerabilities scoutings."
        return 0
    elif [ ! -f "${original_cve_check_file}" ]; then
        bbwarn "Vulnscout: CVE_CHECK file not found: ${original_cve_check_file}. Skipping extra kernel vulnerabilities scouting."
        return 0
    fi

    #Launch the new script to improve the cve report
    python3 "${improve_kernel_cve_script}" \
        --spdx "${spdx_file}" \
        --old-cve-report "${original_cve_check_file}" \
        --new-cve-report "${new_cve_report_file}" \
        --datadir "${WORKDIR}/vulns"
    bbplain "Improve CVE report with extra kernel cves: ${new_cve_report_file}"

    #Create a symlink as every other JSON file in tmp/deploy/images
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.scouted.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.scouted.json

    # Replace the old cve report file in the docker-compose file by the new one
    sed -i -E "s|^([[:space:]]*)-[[:space:]]*.*/yocto_cve_check/[^:]*\.json:ro,Z|\1- ${new_cve_report_file}:/scan/inputs/yocto_cve_check/${IMAGE_NAME}.scouted.json:ro,Z|" "$docker_compose_file"
}
do_scout_extra_kernel_vulns[nostamp] = "1"
do_scout_extra_kernel_vulns[doc] = "Scout extra kernel vulnerabilities and create a new enhanced version of the cve_check file in the deploy directory"
addtask scout_extra_kernel_vulns after do_create_image_sbom_spdx before do_build