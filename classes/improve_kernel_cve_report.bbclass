# Setting to specify the path to the SPDX file to be used for extra kernel vulnerabilities scouting
IMPROVE_KERNEL_SPDX_FILE = "${DEPLOY_DIR_SPDX}/${@d.getVar('MACHINE').replace('-', '_')}/recipes/recipe-${PREFERRED_PROVIDER_virtual/kernel}.spdx.json"

python __anonymous() {
    if not bb.data.inherits_class("cve-check", d):
        bb.fatal("improve_kernel_cve: must inherit cve-check for using this class")
}

python do_image_improve_kernel_cve_report() {
    import os
    import vulnscout.improve_kernel_cve_report as ikc

    # Define input files and paths
    spdx_file = d.getVar('IMPROVE_KERNEL_SPDX_FILE')
    old_cve_report = d.getVar('CVE_CHECK_MANIFEST_JSON')
    imgdeploydir = d.getVar('IMGDEPLOYDIR')
    image_name = d.getVar('IMAGE_NAME')
    image_basename = d.getVar('IMAGE_BASENAME')
    image_machine_suffix = d.getVar('IMAGE_MACHINE_SUFFIX')
    image_name_suffix = d.getVar('IMAGE_NAME_SUFFIX')
    datadir = os.path.join(d.getVar('STAGING_DATADIR_NATIVE'), 'vulns-native')
    new_cve_report = os.path.join(imgdeploydir, f"{image_name}.scouted.json")

    if not spdx_file or not os.path.isfile(spdx_file):
        bb.warn(f"improve_kernel_cve: IMPROVE_KERNEL_SPDX_FILE is empty or file not found: {spdx_file}")
        return
    if not old_cve_report or not os.path.isfile(old_cve_report):
        bb.warn(f"improve_kernel_cve: CVE_CHECK file not found: {old_cve_report}. Skipping extra kernel vulnerabilities scouting.")
        return
    if not os.path.isdir(datadir):
        bb.warn(f"improve_kernel_cve: Vulnerabilities data not found in {datadir}.")
        return

    bb.note(f"improve_kernel_cve: Using SPDX file for extra kernel vulnerabilities scouting: {spdx_file}")
    ikc.kernel_improve_cve_report(spdx_file, old_cve_report, new_cve_report, datadir)
    bb.note(f"improve CVE report with extra kernel CVEs: {new_cve_report}")

    symlink = os.path.join(imgdeploydir, f"{image_basename}{image_machine_suffix}{image_name_suffix}.scouted.json")
    target = f"{image_name}.scouted.json"  # relative, not absolute
    if os.path.islink(symlink) or os.path.exists(symlink):
        os.remove(symlink)
    os.symlink(target, symlink)
}
do_image_improve_kernel_cve_report[depends] += "vulns-native:do_populate_sysroot"
do_image_improve_kernel_cve_report[nostamp] = "1"
do_image_improve_kernel_cve_report[doc] = "Scout extra kernel vulnerabilities and create a new enhanced version of the cve_check file in the deploy directory"
addtask do_image_improve_kernel_cve_report after do_rootfs before do_image_complete
