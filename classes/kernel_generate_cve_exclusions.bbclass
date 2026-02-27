# Generate CVE exclusions for the kernel build
GENERATE_CVE_EXCLUSIONS_OUTPUT_JSON ?= "${T}/cve-exclusion_${LINUX_VERSION}.json"
GENERATE_CVE_EXCLUSIONS_OUTPUT_INC  ?= "${T}/cve-exclusion_${LINUX_VERSION}.inc"

def get_kernel_version(d):
    """Get kernel version from LINUX_VERSION, falling back to PV."""
    linux_version = d.getVar('LINUX_VERSION')
    if not linux_version:
        pv = d.getVar('PV') or ''
        # Strip suffixes like '+git', '-rc1', etc. to get a clean version
        import re
        match = re.match(r'^(\d+\.\d+(?:\.\d+)?)', pv)
        linux_version = match.group(1) if match else pv
        bb.note(f"LINUX_VERSION not defined, falling back to PV-derived version: {linux_version}")
    return linux_version

python do_generate_cve_exclusions() {
    import os
    from packaging.version import Version
    import vulnscout.generate_cve_exclusions as gce

    datadir = os.path.join(d.getVar('STAGING_DATADIR_NATIVE'), 'cvelistv5-native')
    kernel_version = get_kernel_version(d)
    output_json = d.getVar('GENERATE_CVE_EXCLUSIONS_OUTPUT_JSON')
    output_inc = d.getVar('GENERATE_CVE_EXCLUSIONS_OUTPUT_INC')

    if not os.path.isdir(datadir):
        bb.warn(f"generate-cve-exclusions: CVE exclusions source directory not found in {datadir}")
        return

    bb.note(f"Generating CVE exclusions for kernel version {kernel_version}")
    cve_status = gce.generate_cve_exclusions(datadir, kernel_version)

    if output_json:
        gce.write_json_output(cve_status, output_json)
    if output_inc:
        gce.write_inc_output(cve_status, kernel_version, output_inc)

    bb.plain(f"CVE exclusions generated for kernel version {kernel_version} at {output_inc} and {output_json}.")
}
do_generate_cve_exclusions[depends] += "cvelistv5-native:do_populate_sysroot"
do_generate_cve_exclusions[nostamp] = "1"
do_generate_cve_exclusions[doc] = "Generate CVE exclusions for the kernel build. (e.g., cve-exclusion_6.12.json)"
addtask generate_cve_exclusions after do_prepare_recipe_sysroot before do_cve_check

python do_cve_check:prepend() {
    import os
    import json
    kernel_version = get_kernel_version(d)
    json_input_file = d.getVar("GENERATE_CVE_EXCLUSIONS_OUTPUT_JSON")

    if not json_input_file or not os.path.exists(json_input_file):
        bb.warn("generate-cve-exclusions: JSON output file not found, skipping CVE_STATUS injection")
    else:
        with open(json_input_file, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
        cve_status_dict = cve_data.get("cve_status", {})
        count = 0
        for cve_id, info in cve_status_dict.items():
            if info.get("active", True):
                continue
            d.setVarFlag("CVE_STATUS", cve_id, info.get("message", ""))
            count += 1
        bb.note("Loaded %d CVE_STATUS entries from JSON output for kernel %s" % (count, kernel_version))
}
