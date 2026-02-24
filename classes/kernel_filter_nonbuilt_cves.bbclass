python do_kernel_filter_nonbuilt_cves() {
    import os
    import vulnscout.kernel_filter_nonbuilt_cves as kf
    import json

    # Define input files
    input_cve_check = os.path.join(d.getVar('CVE_CHECK_DIR'), d.getVar('PN') + '_cve.json')
    vulns_path = os.path.join(d.getVar('STAGING_DATADIR_NATIVE'), 'vulns-native')
    kernel_build_path = d.getVar('B')

    # Define output files and paths
    workdir_temp_dir = d.getVar('T')
    cve_check_dir = d.getVar('CVE_CHECK_DIR')
    pn = d.getVar('PN')
    image_name = d.getVar('IMAGE_NAME')

    # Check that the required files exist before running the script
    if not os.path.isfile(input_cve_check):
        bb.warn(f"kernel-filter-nonbuilt-cves: cve-check file not found: {input_cve_check}")
        return
    if not os.path.isdir(vulns_path):
        bb.warn(f"kernel-filter-nonbuilt-cves: Vulnerabilities data not found in {vulns_path}")
        return
    if not os.path.isdir(kernel_build_path):
        bb.warn(f"kernel-filter-nonbuilt-cves: Kernel build directory not found: {kernel_build_path}")
        return

    # Step 1: Load Unpatched CVEs
    unfixed = kf.kernel_get_unpatched_cves(input_cve_check)
    bb.note(f"Unpatched kernel CVEs: {len(unfixed)}")

    # Step 2: Get affected programFiles from vulns repo
    affected_files = kf.kernel_get_cve_program_files(vulns_path, unfixed)
    bb.note(f"CVEs with affected files from vulns repo: {len(affected_files)}")

    # Step 3: CVEs with no programFiles are kept as-is
    unfixed_ids = {cve["id"] for cve in unfixed if cve.get("id")}
    unmapped_cves = unfixed_ids - set(affected_files.keys())
    enabled_cves = {cve_id: [] for cve_id in unmapped_cves}
    bb.note(f"CVEs without affected files (kept as active): {len(unmapped_cves)}")

    # Step 4: Build compiled source list from .o.cmd files
    bb.note("Scanning .o.cmd files for compiled sources...")
    compiled_sources = kf.kernel_build_compiled_sources(kernel_build_path)
    bb.note(f"Unique compiled source files found: {len(compiled_sources)}")

    # Step 5: Match CVE programFiles against compiled sources
    kf.kernel_filter_cves_by_compiled_sources(affected_files, compiled_sources, enabled_cves)
    bb.note(f"Total CVEs affecting this kernel build: {len(enabled_cves)}")

    # Step 6: Write remaining and removed to T for do_deploy to pick up
    remaining_path = os.path.join(workdir_temp_dir, image_name + '.kernel_remaining_cves.json')
    with open(remaining_path, 'w', encoding='utf-8') as f:
        json.dump(enabled_cves, f, indent=4)

    removed_cves = {k: v for k, v in affected_files.items() if k not in enabled_cves}
    removed_path = os.path.join(workdir_temp_dir, image_name + '.kernel_removed_cves.json')
    with open(removed_path, 'w', encoding='utf-8') as f:
        json.dump(removed_cves, f, indent=4)

    # Step 7: Write filtered cve-check directly to its final destination
    filtered_path = os.path.join(cve_check_dir, pn + '_cve.json')
    kf.generate_kernel_filtered_cve_check(input_cve_check, enabled_cves, filtered_path)

    bb.note(f"kernel-filter-nonbuilt-cves: Remaining kernel CVEs mapping file: {remaining_path}")
    bb.note(f"kernel-filter-nonbuilt-cves: Removed kernel CVEs not applicable to the current kernel configuration: {removed_path}")
    bb.note(f"kernel-filter-nonbuilt-cves: New cve-check generated report with kernel cves filtered: {filtered_path}")
}
addtask kernel_filter_nonbuilt_cves after do_cve_check before do_deploy
do_kernel_filter_nonbuilt_cves[depends] += "vulns-native:do_populate_sysroot ${PN}:do_compile"
do_kernel_filter_nonbuilt_cves[nostamp] = "1"

do_deploy:append() {
    install -m 0644 "${T}/${IMAGE_NAME}.kernel_remaining_cves.json" "${DEPLOYDIR}/"
    install -m 0644 "${T}/${IMAGE_NAME}.kernel_removed_cves.json" "${DEPLOYDIR}/"
}
