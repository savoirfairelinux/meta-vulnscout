IMPROVE_KERNEL_PREFERRED_PROVIDER = "create-spdx"
IMPROVE_KERNEL_SPDX_FILE = "${DEPLOY_DIR_SPDX}/${@d.getVar('MACHINE').replace('-', '_')}/recipes/recipe-${PREFERRED_PROVIDER_virtual/kernel}.spdx.json"

inherit improve_kernel_cve_report-base