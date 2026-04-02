![VulnScout logo](./doc/vulnscout-logo.jpeg?raw=true)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

`meta-vulnscout` is a Yocto meta-layer that uses
[VulnScout](https://vulnscout.io) to scan a project, export its Software Bill of
Materials (SBOM), and list the vulnerabilities affecting it.

Currently the supported formats are: CycloneDX, SPDX, Yocto JSON files, and
OpenVEX.

## Requirements

- `docker` command

- `python3-packaging` package. If you are running in CQFD, you should add it in
  `.cqfd/docker/Dockerfile`.

##  Installation

Clone the repository into the `sources` directory and add it to your
`build/conf/bblayers.conf` file:

```sh
cd sources
git clone https://github.com/savoirfairelinux/meta-vulnscout.git
```

If you are using submodules to manage your sub-repos, you should include this
meta-layer using the following commands:

```shell
$ cd sources
$ git submodule add https://github.com/savoirfairelinux/meta-vulnscout.git
```

And in your `bblayers.conf` file add the line:

```sh
BBLAYERS += "/path/to/meta-vulnscout"
```

## Configuration

To enable and configure VulnScout, add the following lines to your `local.conf`
or distro config:

```sh
# Required settings for VulnScout
require conf/distro/include/vulnscout-core.inc
```

This configuration enables VulnScout for all image recipes and should be
sufficient for most users. If you want more fine-grained control on which images
are enabling VulnScout, then you can add to your `local.conf` or distro config:

```sh
# Inherit create-spdx to generate SBOMs
# May be required if not using poky distro
INHERIT += "create-spdx"

HOSTTOOLS_NONFATAL += "docker"
```

And then manually `inherit vulnscout` in specific image recipes to enable
VulnScout.

The distro `poky-vulnscout` provided in this repo provides an example of a
complete usage of meta-vulnscout features.

## Extra VulnScout configuration for cve-check improvements

`meta-vulnscout` provides other classes for accurate cve-check file generation.

### Configuration

Add this line to your distro config or `local.conf` to inherit the extra
classes:

```sh
# Enable extra CVE analysis
require conf/distro/include/vulnscout-cve-check.inc
```

### Description

- `kernel_generate_cve_exclusions.bbclass` can be used to integrate a library
  `lib/vulnscout/generate_cve_exclusions_py` derived from the script
  [generate-cve-exclusions.py](https://docs.yoctoproject.org/dev/singleindex.html#generate-cve-exclusions-py).
  \
  It provides extra kernel CVE details and information through the variable
  `CVE_STATUS`. \
  This script is implemented through `conf/distro/include/vulnscout-cve-check.inc`
  It can be manually implement it by a `KERNEL_CLASSES += "kernel_generate_cve_exclusions"`


- `improve_kernel_cve_report.bbclass` can be used to integrate the script
  `improve_kernel_cve_report.py` (reference :
  [improve_kernel_cve_report](https://docs.yoctoproject.org/dev/singleindex.html#improve-kernel-cve-report-py)).
  \
  It reduces CVE false positives by 70%-80% and provides detailed responses
  for all kernel-related CVEs by analyzing the files used to build the kernel. \
  This script is implemented through `conf/distro/include/vulnscout-cve-check.inc`
  It can be manually implement it by a `IMAGE_CLASSES += "improve_kernel_cve_report"`

- `kernel_filter_nonbuilt_cves.bbclass` can be used to update the cve-check file
  by removing CVEs based on elements that aren't present in the built kernel. A
  CVE linked with a driver that isn't compiled doesn't make your kernel
  vulnerable to it. \
  It reduces the number of kernel CVEs to deal with by
  around 70%. \
  This script is implemented through `conf/distro/include/vulnscout-cve-check.inc`
  It can be manually implement it by a `KERNEL_CLASSES += "kernel_filter_nonbuilt_cves"` or
  a simple `inherit kernel_filter_nonbuilt_cves` is required in the kernel recipe. After a kernel
  build tree, new files will be located in your deploy directory. A file with
  `.kernel_remaining_cves.json` extension will contain the remaining active
  CVEs, a second file with `.kernel_removed_cves.json` contains the details of
  CVEs that don't apply to your system. \ Also, the virtual kernel cve-check
  file and the final cve-check manifest will both be affected by
  this class analysis setting all non-built CVEs to `Ignored` status with
  `details` set to `cve-not-compiled-in-kernel` and `description` to
  `kernel_filter_nonbuilt_cves detected that this CVE is not affecting the
  current kernel build.`

## Using VulnScout Web Interface

After a normal build, you should see a new `.vulnscout` folder in `${TOPDIR}/..`
(can be modified with variable `VULNSCOUT_ROOT_DIR`).

The scan and analysis of vulnerabilities can be started with:

```sh
bitbake core-image-minimal -c vulnscout
```

VulnScout Docker container can also be started without rescanning for new CVEs
with the following command:

```sh
bitbake core-image-minimal -c do_vulnscout_no_scan
```

Or you can do it manually with the command:

```shell
docker exec vulnscout /scan/src/entrypoint.sh --serve
```

Without a custom configuration, a web interface will be started at the address
`http://localhost:7275`

### Projects and Variants

meta-vulnscout organises data into *projects* and *variants*.\
 A project typically maps to a product, and variants represent different builds or architectures as the machine, the image or even the distro (e.g. `x86_64`, `aarch64`).

 By default the project name is default and can be changed through the variable `VULNSCOUT_PROJECT` in the *local.conf* file.

And the variant is set as `<distro>_<machine>_<image>` of your build (e.g. poky_qemux86-64_ccore-image-minimal).
It can be changed through the variable `VULNSCOUT_VARIANT` in the *local.conf* file.


## Using VulnScout with a CI

It is possible to launch VulnScout in a CI mode, without the web interface using
the command:

```sh
bitbake core-image-minimal -c vulnscout_ci
```
All the files generated by `vulnscout` will be placed by default here:
`<project_root>/.vulnscout/core-image-minimal/output`

### Options

`vulnscout` in CI mode can be launched with a specific _match condition_ using an
environment variable.

First you need to export the environment variable
`BB_ENV_PASSTHROUGH_ADDITIONS+=" VULNSCOUT_MATCH_CONDITION"`\
For example, using the `export` command:

```bash
export BB_ENV_PASSTHROUGH_ADDITIONS+=" VULNSCOUT_MATCH_CONDITION"
```

Or every time you launch `vulnscout` in the CI mode:

```bash
BB_ENV_PASSTHROUGH_ADDITIONS+=" VULNSCOUT_MATCH_CONDITION" bitbake core-image-minimal -c vulnscout_ci
```
Now you can specify the match condition with the `VULNSCOUT_MATCH_CONDITION`
variable every time you use `vulnscout` in CI mode:

```bash
VULNSCOUT_MATCH_CONDITION="cvss >= 9.0" BB_ENV_PASSTHROUGH_ADDITIONS+=" VULNSCOUT_MATCH_CONDITION" bitbake core-image-minimal -c vulnscout_ci
```

With this command, `vulnscout` will list all the CVEs of the vulnerabilities
with a CVSS score equal to or higher than 9.0.

It's possible to set more than one condition:
```bash
VULNSCOUT_MATCH_CONDITION="cvss >= 9.0 or (cvss >= 7.0 and epss >= 50%)" bitbake core-image-minimal -c vulnscout_ci
```

With this command, `vulnscout` will list all vulnerabilities critical (CVSS >=
9.0) or those with both a high CVSS and EPSS score.

> [!NOTE]
> Setting up the match condition this way will override the
> "VULNSCOUT_MATCH_CONDITION"

> [!WARNING]
> If you set the "VULNSCOUT_MATCH_CONDITION" with the `export` command in your
> shell, it will always use it until you set it to null

## Generating reports

meta-vulnscout is capable of generating built-in reports and even custom ones.
The built-in reports are the following:
  - all_assessments.adoc
  - match_condition.adoc
  - summary.adoc
  - time_estimate.csv
  - vulnerabilities.csv
  - vulnerability_summary.txt

All Custom reports must be placed in the following folder _.vulnscout/custom\_templates_
Custome report should follow the [template format of VulnScout](https://github.com/savoirfairelinux/vulnscout/blob/main/doc/WRITING_TEMPLATES.adoc).

> [!NOTE]
> The custom_templates could be changed through the
> "VULNSCOUT_CUSTOM_TEMPLATES_DIR" variable in the *local.conf* file.

There are two ways to generate reports with meta-vulnscout

### Generating reports without a scan
Multiple reports can be created within one command without a scan.

You must specify the reports you wish to generate to the variable "VULNSCOUT_REPORT" in the *local.conf* file.
By default it will generate the summary.adoc

Example:
``` bash
VULNSCOUT_REPORT = "summary.adoc time_estimate.csv"
```

Then reports can be created without scan using the command:

``` bash
bitbake core-image-minimal -c vulnscout_report
```

The reports are generated by default in the folder `.vulnscout/<image_basename-machine_suffix>/`

### Generating reports during CI scan

When launching a CI scan you can specify one or multiple reports to generate it at the same time.

Specify the reports in the variable "VULNSCOUT_REPORT_CI"

Now when using the command `-c vulnscout_ci` the reports will be automatically generated.

## Exporting SBOM Files

meta-vulnscout can export the enriched project data as standard SBOM formats.
Exported files are written to the outputs directory (default: `.vulnscout/<image_basename-machine_suffix>/`).

To export the SBOM files, you have to specify the files in the variable "VULNSCOUT_EXPORT" in the *local.conf*.

For now you can export three types of SBOM:
  - cdx
  - spdx
  - openvex

Finally you just need to launch the command:

``` bash
bitbake core-image-minimal -c vulnscout_export
```

### Use environment variables in templates

In VulnScout templates, you can use environment variables as stated in the
documentation. These variables should be automatically detected if they are in a
template in the `custom_templates` directory, and that the template is in use in
`VULNSCOUT_ENV_GENERATE_DOCUMENTS`.

## Accelerate NVD database download

For faster NVD database downloads during VulnScout setup, you can set an NVD
key with the variable `NVDCVE_API_KEY`.

Yocto Documentation reference : https://docs.yoctoproject.org/ref-manual/variables.html#term-NVDCVE_API_KEY

You can generate a new NVD key at : https://nvd.nist.gov/developers/request-an-api-key

## Using the web interface with a building Docker container

The Yocto task `vulnscout` creates and starts the Docker container with a Web
interface available.

Using a Docker container to build the project requires additional configuration
to access the web interface.

Indeed, the web interface won't be mapped to the host if the building Docker
container is not properly configured.

CQFD requires adding `docker-cli` (for Ubuntu 22.04 and earlier)
*.cqfd/docker/Dockerfile* and exporting the following variable:

``` bash
export CQFD_EXTRA_RUN_ARGS="-v /run/docker.sock:/run/docker.sock"
```

For a permanent change, you can instead modify the `.cqfdrc` file with
`docker_run_args="-v /run/docker.sock:/run/docker.sock"`.

Now, you can build your image and use the `vulnscout` task with one of these
commands:

**If you use CQFD and KAS**
``` bash
cqfd kas shell -c "bitbake -c <your_Yocto_image> -c vulnscout"
```

**If you use CQFD and the script build.sh made by Savoir-faire Linux**
```bash
cqfd run ./build.sh -- bitbake <your_Yocto_image> -c vulnscout
```

## Using [meta-sbom-cve-check](https://github.com/bootlin/meta-sbom-cve-check)

The output of `meta-sbom-cve-check` is supported in VulnScout. However, this
layer is incompatible with the cve-check improvements provided in
`meta-vulnscout`. As a consequence, do not use
`conf/distro/include/vulnscout-cve-check.inc` with `meta-sbom-cve-check`.

## Result

![Screenshot](doc/vulnscout-ui.png)

## Variables Glossary

meta-vulnscout can be configured through variables in the *local.conf*.
Here is a recap of all the variable and their impact:

- VULNSCOUT_ROOT_DIR : Root directory of the ./vulnscout
- VULNSCOUT_BASE_DIR : Base directory of the ./vulnscout configuration and output files
- VULNSCOUT_DEPLOY_DIR : Directory of the ouput files (reports, exports, ...)
- VULNSCOUT_CACHE_DIR : Directory of the cache used by vulnscout (database, docker config file)
- VULNSCOUT_CUSTOM_TEMPLATES_DIR : Directory used to implement custom template to vulnscout
- VULNSCOUT_CONFIG_FILE : Docker config file
- VULNSCOUT_VARIANT : Name of the variant used in vulnscout
- VULNSCOUT_PROJECT : Name of the project used in vulnscout
- VULNSCOUT_EXPORT : SBOM files to generate with the command `-c vulnscout_export` ( the value has to bee spdx, openvex or cdx)
- VULNSCOUT_REPORT : Reports to generate with the command `-c vulnscout_report` using templates.
- VULNSCOUT_REPORT_CI : Reports generated automatically when during `-c vulnscout_ci`
- VULNSCOUT_IMAGE_VERSION : Version of the container image to use. If the version set in the variable is not the same as the container image used, recreate the vulnscout container.
- VULNSCOUT_IMAGE : Name of the container image to use for vulnscout container.
- VULNSCOUT_ENV_VERBOSE_MODE : Enable or disable the verbose mode (false by default)
- VULNSCOUT_ENV_FLASK_RUN_PORT : Port vulnscout used for the Web Interface (7275 by default)
- VULNSCOUT_ENV_FLASK_RUN_HOST : IP used on the host for the Web Interface (0.0.0.0 by default)
- VULNSCOUT_ENV_IGNORE_PARSING_ERRORS : Enable or disable to ignore parsing error found in the entry SBOM files. (false by default)
- VULNSCOUT_MATCH_CONDITION : Match-condition to set by default to avoid precise it everytime during the command `-c vulnscout_ci`

## License

`Copyright (C) 2025-2026 Savoir-faire Linux, Inc.`

meta-vulnscout is released under the Apache License 2.0.
