# This class provides a task to filter out CVEs that are not applicable to the current kernel configuration

python do_clean_kernel_filter_nonbuilt_cves() {
    import os, glob
    deploy_dir = d.expand('${DEPLOY_DIR_IMAGE}')
    for f in glob.glob(os.path.join(deploy_dir, '*kernel_removed_cves.json')):
        bb.note("Removing " + f)
        os.remove(f)
    for f in glob.glob(os.path.join(deploy_dir, '*kernel_remaining_cves.json')):
        bb.note("Removing " + f)
        os.remove(f)
}

python do_clean:append() {
    bb.build.exec_func("do_clean_kernel_filter_nonbuilt_cves",d)
}

python do_cve_check:append() {
    bb.build.exec_func("do_kernel_filter_nonbuilt_cves",d)
}
do_cve_check[prefuncs] += "do_clean_kernel_filter_nonbuilt_cves"
do_cve_check[depends] += "vulns-native:do_populate_sysroot ${PN}:do_compile"

do_kernel_filter_nonbuilt_cves() {
    # Define input files
    kernel_filter_nonbuilt_cves_script="${SCRIPT_FOLDER}/kernel_filter_nonbuilt_cves.py"
    input_cve_check="${CVE_CHECK_DIR}/${PN}_cve.json"
    vulns_path="${STAGING_DATADIR_NATIVE}/vulns-native"

    # Check that the required files exist before running the script
    if [ ! -f "${input_cve_check}" ]; then
        bbwarn "kernel-filter-nonbuilt-cves: cve-check file not found: ${input_cve_check}"
        return 0
    fi
    if [ ! -f "${kernel_filter_nonbuilt_cves_script}" ]; then
        bbwarn "kernel-filter-nonbuilt-cves: kernel_filter_nonbuilt_cves.py script not found: ${kernel_filter_nonbuilt_cves_script}"
        return 0
    fi
    if [ ! -d "${vulns_path}" ]; then
        bbwarn "kernel-filter-nonbuilt-cves: Vulnerabilities data not found in ${vulns_path}."
        return 0
    fi
    if [ ! -d "${B}" ]; then
        bbwarn "kernel-filter-nonbuilt-cves: Kernel build directory not found: ${B}"
        return 0
    fi

    # Build the full command as a string (for debug)
    KERNEL_CVE_FILTER_CMD="python3 ${kernel_filter_nonbuilt_cves_script} \
        --vulns-path ${vulns_path} \
        --input-cve-check ${input_cve_check} \
        --input-build-kernel-path ${B} \
        --output-filename-cve-check ${PN}_cve.json \
        --output-filename-remaining-cves ${IMAGE_NAME}.kernel_remaining_cves.json \
        --output-filename-removed-cves ${IMAGE_NAME}.kernel_removed_cves.json \
        --output-path-analysis ${DEPLOY_DIR_IMAGE} \
        --output-path-cve-check ${CVE_CHECK_DIR}"

    # Debug: print the exact command that will be executed
    bbnote "Kernel CVE filter command:"
    bbnote "  ${KERNEL_CVE_FILTER_CMD}"

    # Launch the kernel filtering script
    ${KERNEL_CVE_FILTER_CMD}

    # Success message which returns the generated files
    bbplain "kernel-filter-nonbuilt-cves: Remaining kernel CVEs mapping file: ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_remaining_cves.json"
    bbplain "kernel-filter-nonbuilt-cves: Removed kernel CVEs not applicable to the current kernel configuration: ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_removed_cves.json"
    bbplain "kernel-filter-nonbuilt-cves: New cve-check generated report with kernel cves filtered: ${CVE_CHECK_DIR}/${PN}_cve.json"

    #Create a symlink as every other JSON file in tmp/deploy/images
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_remaining_cves.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.kernel_remaining_cves.json
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_removed_cves.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.kernel_removed_cves.json
}
do_kernel_filter_nonbuilt_cves[prefuncs] += "do_clean_kernel_filter_nonbuilt_cves"
do_kernel_filter_nonbuilt_cves[depends] += "vulns-native:do_populate_sysroot ${PN}:do_compile"
do_kernel_filter_nonbuilt_cves[nostamp] = "1"
do_kernel_filter_nonbuilt_cves[doc] = "Run kernel_remove_out_of_config_cves.py with the current defconfig to filter out CVEs not applicable to the current kernel configuration and generate a new cve-check report and a mapping file of remaining kernel CVEs"
addtask kernel_filter_nonbuilt_cves after do_cve_check

# Task to re-run the kernel CVE filtering with the same input files but without re-running cve-check, useful for testing and debugging the kernel filtering script without having to re-run the entire cve-check process
python do_kernel_filter_nonbuilt_cves_no_scan() {
    bb.build.exec_func("do_kernel_filter_nonbuilt_cves",d)
}
do_kernel_filter_nonbuilt_cves_no_scan[depends] += "vulns-native:do_populate_sysroot"
do_kernel_filter_nonbuilt_cves_no_scan[nostamp] = "1"
do_kernel_filter_nonbuilt_cves_no_scan[doc] = "Run kernel_remove_out_of_config_cves.py with the current defconfig to filter out CVEs not applicable to the current kernel configuration and generate a new cve-check report and a mapping file of remaining kernel CVEs"
addtask kernel_filter_nonbuilt_cves_no_scan
