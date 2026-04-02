# Vulnscout class variables for Yocto Project
VULNSCOUT_ROOT_DIR ?= "${TOPDIR}/.."
VULNSCOUT_BASE_DIR ?= "${VULNSCOUT_ROOT_DIR}/.vulnscout"
VULNSCOUT_DEPLOY_DIR ?= "${VULNSCOUT_BASE_DIR}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}"
VULNSCOUT_CACHE_DIR ?= "${VULNSCOUT_BASE_DIR}/cache"
VULNSCOUT_CUSTOM_TEMPLATES_DIR ?= "${VULNSCOUT_BASE_DIR}/custom_templates"
VULNSCOUT_CONFIG_FILE ?= "${VULNSCOUT_CACHE_DIR}/config.env"

# Vulnscout parameters for the scan, report and export configuration
VULNSCOUT_VARIANT ?= "${DISTRO}_${MACHINE}_${IMAGE_BASENAME}"
VULNSCOUT_PROJECT ?= "default"
VULNSCOUT_EXPORT ?= "spdx openvex"
VULNSCOUT_REPORT ?= ""
VULNSCOUT_REPORT_CI ?= ""

# Repo and version of vulnscout to use
VULNSCOUT_DOCKER_IMAGE ?= "sflinux/vulnscout"
VULNSCOUT_GIT_URI ?= "https://github.com/savoirfairelinux/vulnscout.git"

# Variables for the vulnscout configuration
VULNSCOUT_ENV_VERBOSE_MODE ?= "false"
VULNSCOUT_ENV_FLASK_RUN_PORT ?= "7275"
VULNSCOUT_ENV_FLASK_RUN_HOST ?= "0.0.0.0"
VULNSCOUT_ENV_IGNORE_PARSING_ERRORS ?= 'false'
VULNSCOUT_MATCH_CONDITION ?= ""

# Variable for the Vulnerabilities files
SPDX_3_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.json"
SPDX_2_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.tar.zst"
CVE_CHECK_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json"
SCOUTED_CVE_CHECK_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.scouted.json"
SBOM_CVE_CHECK_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}${@d.getVarFlag("SBOM_CVE_CHECK_EXPORT_FILE", "ext")}"

python __anonymous() {
    if bb.data.inherits_class("sbom-cve-check", d):
        bb.build.addtask("do_setup_vulnscout", "do_build", "do_sbom_cve_check", d)
    elif bb.data.inherits_class("create-spdx-2.2", d):
        bb.build.addtask("do_setup_vulnscout", "do_build", "do_image_complete", d)
    elif bb.data.inherits_class("create-spdx-3.0", d):
        bb.build.addtask("do_setup_vulnscout", "do_build", "do_create_image_sbom_spdx", d)
    else:
        bb.fatal("Neither create-spdx, nor create-spdx-3.0, nor create-spdx-2.2 class is inherited, please inherit one of these classes in your distro config or local.conf.")
}

# Helper function to check if Vulnscout required files are present on the host
check_vulnscout_requirements() {
    # Check the CVE-Check already exist
    if ${@bb.utils.contains('INHERIT', 'cve-check', 'true', 'false', d)}; then
        if ${@'true' if d.getVarFlag('do_image_improve_kernel_cve_report', 'task') else 'false'}; then
            if [ ! -e "${SCOUTED_CVE_CHECK_PATH}" ]; then
                bbfatal "Scouted CVE-Check file not found at ${SCOUTED_CVE_CHECK_PATH}. Please rebuild the image."
            fi
        elif [ ! -e "${CVE_CHECK_PATH}" ]; then
            bbfatal "CVE-Check file not found at ${CVE_CHECK_PATH}. Please enable 'cve-check' in INHERIT to generate it and rebuild the image."
        fi
    fi

    # Check the SPDX-2.2 or SPDX-3.0 files already exist based on INHERIT
    if ${@'true' if bb.data.inherits_class("sbom-cve-check", d) else 'false'}; then
        if [ ! -e "${SBOM_CVE_CHECK_PATH}" ]; then
            bbfatal "sbom-cve-check file not found at ${SBOM_CVE_CHECK_PATH}. Please rebuild the image."
        fi
    elif ${@'true' if bb.data.inherits_class("create-spdx-3.0", d) else 'false'}; then
        if [ ! -e "${SPDX_3_PATH}" ]; then
            bbfatal "SPDX-3.0 file not found at ${SPDX_3_PATH}. Please rebuild the image."
        fi
    elif ${@'true' if bb.data.inherits_class("create-spdx-2.2", d) else 'false'}; then
        if [ ! -e "${SPDX_2_PATH}" ]; then
            bbfatal "SPDX-2.2 file not found at ${SPDX_2_PATH}. Please rebuild the image."
        fi
    fi
}

do_setup_vulnscout() {
    check_vulnscout_requirements

    # Create an output directory for vulnscout configuration
    mkdir -p ${VULNSCOUT_DEPLOY_DIR}

    if [ ! -e "${VULNSCOUT_BASE_DIR}/.gitignore" ]; then
        cat > "${VULNSCOUT_BASE_DIR}/.gitignore" <<EOF
cache/
EOF
    fi

    #  Populate the config file
    if [ ! -f "${VULNSCOUT_CONFIG_FILE}" ]; then
    mkdir -p "${VULNSCOUT_CACHE_DIR}"
    cat > ${VULNSCOUT_CONFIG_FILE} <<EOF
FLASK_RUN_PORT=${VULNSCOUT_ENV_FLASK_RUN_PORT}
FLASK_RUN_HOST=${VULNSCOUT_ENV_FLASK_RUN_HOST}
IGNORE_PARSING_ERRORS=${VULNSCOUT_ENV_IGNORE_PARSING_ERRORS}
VERBOSE_MODE=${VULNSCOUT_ENV_VERBOSE_MODE}
USER_UID=$(id -u)
USER_GID=$(id -g)
VULNSCOUT_VERSION="$(docker inspect "${VULNSCOUT_DOCKER_IMAGE}" --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null || echo unknown)"
EOF
        echo "Created default config at ${VULNSCOUT_CONFIG_FILE}"
    fi

    retry_count=0
    containers=$(docker ps -a --filter 'name=vulnscout' --format '{{.ID}}')
    while [ -n "$containers" ]; do
        count=$(echo "$containers" | wc -l)
        bbplain "Found $count vulnscout container(s), deleting..."
        success=true
        for cid in $containers; do
            if ! docker rm -f "$cid"; then
                bbwarn "Failed to delete container $cid"
                success=false
            fi
        done
        if [ "$success" = "true" ]; then
            retry_count=0
        else
            retry_count=$(expr "$retry_count" + 1)
            if [ "$retry_count" -ge 5 ]; then
                bbfatal "Cannot delete old vulnscout containers. Exiting..."
            fi
        fi
        containers=$(docker ps -a --filter 'name=vulnscout' --format '{{.ID}}')
    done

    set --
    while IFS='=' read -r key value; do
        [ -z "$key" ] && continue
        [ "${key#\#}" = "$key" ] || continue
        set -- "$@" -e "${key}=${value}"
    done < "${VULNSCOUT_CONFIG_FILE}"

    docker run -d --name vulnscout \
        -p 7275:7275 \
        "$@" \
        -v "${VULNSCOUT_CACHE_DIR}":/cache/vulnscout \
        -v "${VULNSCOUT_DEPLOY_DIR}":/scan/outputs \
        -v "${VULNSCOUT_CONFIG_FILE}":/etc/vulnscout/config.env \
        "${VULNSCOUT_DOCKER_IMAGE}" daemon
    # Wait for the container process to be ready to accept exec calls
    retries=15
    until docker exec vulnscout true 2>/dev/null; do
        retries=$(expr "$retries" - 1)
        if [ "$retries" -le 0 ]; then
            echo "Error: container failed to start. Check 'docker logs vulnscout'."
            exit 1
        fi
        sleep 1
    done

    bbplain "Vulnscout Setup Succeed: Docker Env file set at ${VULNSCOUT_CONFIG_FILE}"

}
do_setup_vulnscout[nostamp] = "1"
do_setup_vulnscout[doc] = "Configure the env file and create a new container"

# Helper function to find files in a directory and its subdirectories based on a pattern
def find_all(name, path):
    import os
    import fnmatch
    result = []
    for root, dirs, files in os.walk(path):
        for filename in files:
            if fnmatch.fnmatch(filename, f"*{name}*"):
                result.append(os.path.join(root, filename))
    return result

# Helper function to copy reports templates in the container
# If there is not templates on the host, it try anyway
# they may be already present in the container
def copy_reports_to_container(reports, folder):
    import subprocess
    import os

    cmd = []

    # Retrieve the templates specified
    templates = []
    for report in reports:
        templates.extend(find_all(report, folder))

    # Copy the templates specified in the container
    for template in templates:
        subprocess.run(['docker', 'cp', template, 'vulnscout:/tmp/'], check=True)
        template_in_container = f"/tmp/{os.path.basename(template)}"
        cmd += ['--report', template_in_container]
    # If no template on the host, try the report on the container
    if not templates:
        for report in reports:
            cmd += ['--report', report]
    return cmd

# Helper function to stop the container
def stop_container():
    import subprocess
    try:
        subprocess.run(['docker', 'stop', 'vulnscout'], check=True)
    except subprocess.CalledProcessError as e:
        bb.fatal(f"Failed to stop docker container: {e}")

def print_generated_files(files, deploy_dir):
    generated_files = []
    for file in files:
        generated_files.extend(find_all(file, deploy_dir))
    for file in generated_files:
        bb.plain(f"Generated file: {file}")

python do_vulnscout_ci() {
    import subprocess
    import os

    # Retrieve project and variant information
    variant = d.getVar("VULNSCOUT_VARIANT")
    project = d.getVar("VULNSCOUT_PROJECT")
    output_vulnscout = d.getVar("VULNSCOUT_DEPLOY_DIR")
    template_folder = (d.getVar("VULNSCOUT_CUSTOM_TEMPLATES_DIR"))
    report_ci = (d.getVar("VULNSCOUT_REPORT_CI") or "").split()

    # Check if a match_condition has been set, if not failed.
    match_condition = d.getVar("VULNSCOUT_MATCH_CONDITION")
    if match_condition and report_ci:
        bb.warn(
            f"\nLaunching vulnscout in CI mode with match condition set has: " + match_condition + "\n"
            f"Generating scan report " + ", ".join(report_ci) + " Scanning ..." )
    elif match_condition:
        bb.warn(f"Launching vulnscout in CI mode with match condition set has: " + match_condition + " Scanning ..." )
    else:
        bb.fatal(f"Launching vulnscout in CI mode without match condition. Please set a match condition.")

    # Launch the vulnscout in CI with the match condition
    cmd = ['docker', 'exec', 'vulnscout', '/scan/src/entrypoint.sh', '--project', project, '--variant', variant]
    if match_condition:
        cmd += ['--match-condition', match_condition]
    if report_ci:
        # Copy the custom templates or use the ones in the container
        cmd += copy_reports_to_container(report_ci, template_folder)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # Print the logs in the current terminal
    for line in process.stdout:
        bb.plain(line.rstrip())
    process.wait()
    docker_exit_code = process.returncode

    # If the container ended with a error code, stop the code and print it.
    if docker_exit_code == 2:
        bb.fatal(
            f"\n----------------Vulnscout trigger match_condition----------------\n"
            f"----------Trigger condition set : {match_condition}---------- \n"
            f"\n---Vulnscout exit with code 2 due to match condition triggered: {match_condition}---\n"
            f"---Vulnscout has generated multiple files here : {output_vulnscout} ---\n" )
    else:
        bb.plain(
            f"\n---Vulnscout scan completed without triggering match condition: {match_condition}---\n"
            f"\n---Vulnscout has generated multiple files here : {output_vulnscout} ---\n" )

    if report_ci:
        # Retrieve the generated files and print them in the current terminal
        print_generated_files(report_ci, output_vulnscout)

    # Stop the container after use
    stop_container()
}
do_vulnscout_ci[nostamp] = "1"
do_vulnscout_ci[doc] = "Launch VulnScout in non-interactive mode. VULNSCOUT_FAIL_CONDITION can be used to set a fail condition"
addtask vulnscout_ci after do_setup_vulnscout

python do_vulnscout() {
    import os
    import subprocess

    # Retrieve project and variant information
    variant = d.getVar("VULNSCOUT_VARIANT")
    project = d.getVar("VULNSCOUT_PROJECT")

    # Retrieve paths for SPDX and CVE-Check files
    spdx_3_path = d.getVar("SPDX_3_PATH")
    spdx_2_path = d.getVar("SPDX_2_PATH")
    cve_check_path = d.getVar("CVE_CHECK_PATH")
    scouted_cve_check_path = d.getVar("SCOUTED_CVE_CHECK_PATH")
    sbom_cve_check_path = d.getVar("SBOM_CVE_CHECK_PATH")

    # Determine which SPDX file to use based on INHERIT
    if bb.data.inherits_class("create-spdx-3.0", d):
        spdx_used_path = spdx_3_path
    else:
        spdx_used_path = spdx_2_path

    spdx_real_path = os.path.realpath(spdx_used_path)

    # Determine which CVE-Check file to use
    if d.getVarFlag('do_image_improve_kernel_cve_report', 'task'):
        cve_check_used_path = scouted_cve_check_path
    else:
        cve_check_used_path = cve_check_path

    cve_check_real_path = os.path.realpath(cve_check_used_path)

    # Copy the SPDX and CVE-Check files into the container
    subprocess.run(['docker', 'cp', spdx_real_path, 'vulnscout:/tmp/'], check=True)
    subprocess.run(['docker', 'cp', cve_check_real_path, 'vulnscout:/tmp/'], check=True)

    # Launch Vulnscout in a new terminal and adding the SPDX and CVE-Check files in the database
    spdx_in_container = f"/tmp/{os.path.basename(spdx_real_path)}"
    cve_check_in_container = f"/tmp/{os.path.basename(cve_check_real_path)}"
    cmd = f"docker exec vulnscout /scan/src/entrypoint.sh --project {project} --variant {variant} --add-spdx {spdx_in_container} --add-cve-check {cve_check_in_container} --serve ; echo; echo Container exited. Press any key to close...; read x"
    oe_terminal(cmd, "Vulnscout Container Logs", d)

    # Stop the container after use
    stop_container()
}
do_vulnscout[nostamp] = "1"
do_vulnscout[doc] = "Open a new terminal and launch VulnScout web interface through a Docker container"
addtask vulnscout after do_setup_vulnscout

python do_vulnscout_export() {
    import subprocess
    import fnmatch
    import os

    # Retrieve the export formats and deploy directory
    exports = (d.getVar("VULNSCOUT_EXPORT") or "").split()
    deploy_dir = d.getVar("VULNSCOUT_DEPLOY_DIR")
    cmd_export = ""

    # Check if the export formats are valid
    for export in exports:
        if export not in ["spdx", "cdx", "openvex"]:
            bb.fatal(f"Invalid export format: {export}. Supported formats are: spdx, cdx, openvex.")
        cmd_export += "--export-" + export + " "

    # Launch the creation of all the export files
    subprocess.run(['docker', 'exec', 'vulnscout', '/scan/src/entrypoint.sh'] + cmd_export.split(), check=True)

    # Retrieve the generated files and print them in the current terminal
    print_generated_files(exports, deploy_dir)

    # Stop the container after use
    stop_container()
}
do_vulnscout_export[nostamp] = "1"
do_vulnscout_export[doc] = "Generate export files from VulnScout in a Docker container"
addtask vulnscout_export after do_setup_vulnscout

python do_vulnscout_report() {
    import subprocess
    import fnmatch
    import os

    # Retrieve the custom templates, report names and deploy directory
    template_folder = (d.getVar("VULNSCOUT_CUSTOM_TEMPLATES_DIR"))
    reports = (d.getVar("VULNSCOUT_REPORT") or "").split()
    deploy_dir = d.getVar("VULNSCOUT_DEPLOY_DIR")
    cmd_report = ""

    # Call the function to copy the template in the container
    cmd_report = copy_reports_to_container(reports, template_folder)

    # Launch the creation of all the reports
    subprocess.run(['docker', 'exec', 'vulnscout', '/scan/src/entrypoint.sh'] + cmd_report, check=True)

    # Retrieve the generated files and print them in the current terminal
    print_generated_files(reports, deploy_dir)

    # Stop the container after use
    stop_container()
}
do_vulnscout_report[nostamp] = "1"
do_vulnscout_report[doc] = "Generate Vulnscout report files from custom templates"
addtask do_vulnscout_report after do_setup_vulnscout

python do_vulnscout_no_scan(){
    import subprocess

    # Launching Vulnscout without scan
    cmd = f"docker exec vulnscout /scan/src/entrypoint.sh --serve ; echo; echo Container exited. Press any key to close...; read x"
    oe_terminal(cmd, "Vulnscout Container Logs", d)

    # Stop the container after use
    stop_container()
}
do_vulnscout_no_scan[nostamp] = "1"
do_vulnscout_no_scan[doc] = "Open a new terminal and launch VulnScout web interface in a Docker container without scanning the image"
addtask vulnscout_no_scan after do_setup_vulnscout
