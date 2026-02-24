# Optional: add kernel-generate-cve-exclusions class to generate CVE exclusion files for the kernel
inherit kernel_generate_cve_exclusions

# Optional: add kernel-filter-nonbuilt-cves class to filter out CVEs not applicable to the current kernel defconfig
inherit kernel_filter_nonbuilt_cves
