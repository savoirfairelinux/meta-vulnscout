# Setting to specify the path to the SPDX file to be used for extra kernel vulnerabilities scouting
IMPROVE_KERNEL_SPDX_FILE = "${DEPLOY_DIR_SPDX}/${@d.getVar('MACHINE').replace('-', '_')}/recipes/recipe-${PREFERRED_PROVIDER_virtual/kernel}.spdx.json"

do_scout_extra_kernel_vulns() {
    new_cve_report_file="${IMGDEPLOYDIR}/${IMAGE_NAME}.scouted.json"
    improve_kernel_cve_script="${VULNSCOUT_SCRIPT_FOLDER}/improve_kernel_cve_report.py"

    # Check that IMPROVE_KERNEL_SPDX_FILE is set and the file exists
    if [ -z "${IMPROVE_KERNEL_SPDX_FILE}" ] || [ ! -f "${IMPROVE_KERNEL_SPDX_FILE}" ]; then
        bbwarn "improve_kernel_cve: IMPROVE_KERNEL_SPDX_FILE is empty or file not found: ${IMPROVE_KERNEL_SPDX_FILE}"
        return 0
    fi
    if [ ! -f "${CVE_CHECK_MANIFEST_JSON}" ]; then
        bbwarn "improve_kernel_cve: CVE_CHECK file not found: ${CVE_CHECK_MANIFEST_JSON}. Skipping extra kernel vulnerabilities scouting."
        return 0
    fi
    if [ ! -f "${improve_kernel_cve_script}" ]; then
        bbwarn "improve_kernel_cve: improve_kernel_cve_report.py not found in ${COREBASE}."
        return 0
    fi
    if [ ! -d "${STAGING_DATADIR_NATIVE}/vulns-native" ]; then
        bbwarn "improve_kernel_cve: Vulnerabilities data not found in ${STAGING_DATADIR_NATIVE}/vulns-native."
        return 0
    fi

    #Run the improve_kernel_cve_report.py script
    bbplain "improve_kernel_cve: Using SPDX file for extra kernel vulnerabilities scouting: ${IMPROVE_KERNEL_SPDX_FILE}"
    python3 "${improve_kernel_cve_script}" \
        --spdx "${IMPROVE_KERNEL_SPDX_FILE}" \
        --old-cve-report "${CVE_CHECK_MANIFEST_JSON}" \
        --new-cve-report "${new_cve_report_file}" \
        --datadir "${STAGING_DATADIR_NATIVE}/vulns-native"
    bbplain "improve CVE report with extra kernel cves: ${new_cve_report_file}"

    #Create a symlink as every other JSON file in tmp/deploy/images
    ln -sf ${IMAGE_NAME}.scouted.json ${IMGDEPLOYDIR}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.scouted.json
}
do_scout_extra_kernel_vulns[depends] += "vulns-native:do_populate_sysroot"
do_scout_extra_kernel_vulns[nostamp] = "1"
do_scout_extra_kernel_vulns[doc] = "Scout extra kernel vulnerabilities and create a new enhanced version of the cve_check file in the deploy directory"
addtask do_scout_extra_kernel_vulns after do_rootfs before do_image_complete
