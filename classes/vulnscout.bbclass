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
VULNSCOUT_EXPORT ?= "cdx openvex spdx"
VULNSCOUT_REPORT ?= "summary.adoc"
VULNSCOUT_REPORT_CI ?= "match_condition.adoc"

# Repo and version of vulnscout to use
VULNSCOUT_IMAGE_VERSION ?= "v0.23"
VULNSCOUT_IMAGE ?= "sflinux/vulnscout"

# Container engine command: "docker" or "podman"
VULNSCOUT_CONTAINER_ENGINE ?= "docker"

# Variables for the vulnscout configuration
VULNSCOUT_ENV_VERBOSE_MODE ?= "false"
VULNSCOUT_ENV_FLASK_RUN_PORT ?= "7275"
VULNSCOUT_ENV_FLASK_RUN_HOST ?= "0.0.0.0"
VULNSCOUT_ENV_IGNORE_PARSING_ERRORS ?= 'false'
VULNSCOUT_MATCH_CONDITION ?= ""

# Variable for the Vulnerabilities files
SPDX_3_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.json"
CVE_CHECK_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json"
SCOUTED_CVE_CHECK_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.scouted.json"
SBOM_CVE_CHECK_SPDX3_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}${@d.getVarFlag("SBOM_CVE_CHECK_EXPORT_SPDX3", "ext")}"

python __anonymous() {
    if bb.data.inherits_class("sbom-cve-check", d):
        bb.build.addtask("do_setup_vulnscout", "do_build", "do_sbom_cve_check", d)
    elif bb.data.inherits_class("create-spdx-3.0", d):
        bb.build.addtask("do_setup_vulnscout", "do_build", "do_create_image_sbom_spdx", d)
    else:
        bb.fatal("Neither sbom-cve-check nor create-spdx-3.0 class is inherited. Please inherit one of these classes in your distro config or local.conf.")
}

# Helper function to check if Vulnscout required files are present on the host
check_vulnscout_requirements() {
    # Check the existence of files based on classes inherited
    if ${@'true' if bb.data.inherits_class("sbom-cve-check", d) else 'false'}; then
        if [ ! -e "${SBOM_CVE_CHECK_SPDX3_PATH}" ]; then
            bbfatal "sbom-cve-check SPDX-3.0 format file not found at ${SBOM_CVE_CHECK_SPDX3_PATH}. Please rebuild the image."
        fi
    else
        if ${@bb.utils.contains('INHERIT', 'cve-check', 'true', 'false', d)}; then
            if ${@'true' if d.getVarFlag('do_image_improve_kernel_cve_report', 'task') else 'false'}; then
                if [ ! -e "${SCOUTED_CVE_CHECK_PATH}" ]; then
                    bbfatal "Scouted CVE-Check file not found at ${SCOUTED_CVE_CHECK_PATH}. Please rebuild the image."
                fi
            elif [ ! -e "${CVE_CHECK_PATH}" ]; then
                bbfatal "CVE-Check file not found at ${CVE_CHECK_PATH}. Please enable 'cve-check' in INHERIT to generate it and rebuild the image."
            fi
        fi
        if ${@'true' if bb.data.inherits_class("create-spdx-3.0", d) else 'false'}; then
            if [ ! -e "${SPDX_3_PATH}" ]; then
                bbfatal "SPDX-3.0 file not found at ${SPDX_3_PATH}. Please rebuild the image."
            fi
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
EOF
        echo "Created default config at ${VULNSCOUT_CONFIG_FILE}"

    else
        # For each parameter, only update the config file if the value differs from the variable
        for entry in \
            "FLASK_RUN_PORT:${VULNSCOUT_ENV_FLASK_RUN_PORT}" \
            "FLASK_RUN_HOST:${VULNSCOUT_ENV_FLASK_RUN_HOST}" \
            "IGNORE_PARSING_ERRORS:${VULNSCOUT_ENV_IGNORE_PARSING_ERRORS}" \
            "VERBOSE_MODE:${VULNSCOUT_ENV_VERBOSE_MODE}"; do
            key="${entry%%:*}"
            var_value="${entry#*:}"
            current_value=$(grep "^${key}=" "${VULNSCOUT_CONFIG_FILE}" | cut -d= -f2-)
            if [ "$current_value" != "$var_value" ]; then
                sed -i "s|^${key}=.*|${key}=${var_value}|" "${VULNSCOUT_CONFIG_FILE}"
            fi
        done

    fi

    # Prefer host binaries: the native sysroot ships a non-setuid newuidmap
    # that breaks rootless podman
    export PATH="/usr/bin:/usr/sbin:$PATH"

    if ! command -v ${VULNSCOUT_CONTAINER_ENGINE} >/dev/null 2>&1; then
        bbfatal "Error: '${VULNSCOUT_CONTAINER_ENGINE}' was not found. Install Docker or Podman, or set VULNSCOUT_CONTAINER_ENGINE to the right command."
    fi
    engine_err=$(${VULNSCOUT_CONTAINER_ENGINE} info 2>&1 >/dev/null) || {
        case "$engine_err" in
            *"permission denied"*)
                bbfatal "Error: permission denied while connecting to '${VULNSCOUT_CONTAINER_ENGINE}'. For Docker, add your user to the 'docker' group (sudo usermod -aG docker \$USER, then re-login). Details: $engine_err" ;;
            *)
                bbfatal "Error: '${VULNSCOUT_CONTAINER_ENGINE}' is not usable. Is the daemon/socket running? Details: $engine_err" ;;
        esac
    }

    counter=0
    while [ $counter -lt 5 ]; do
        containers=$(${VULNSCOUT_CONTAINER_ENGINE} ps -a --filter 'name=vulnscout' --format '{{.ID}}')
        if [ -z "$containers" ]; then
            docker_check_image=$(${VULNSCOUT_CONTAINER_ENGINE} images -q "${VULNSCOUT_IMAGE}:${VULNSCOUT_IMAGE_VERSION}")
            if [ -z "$docker_check_image" ]; then
                bbplain "Pulling vulnscout image ${VULNSCOUT_IMAGE}:${VULNSCOUT_IMAGE_VERSION} from DockerHub..."
                if ! ${VULNSCOUT_CONTAINER_ENGINE} pull "${VULNSCOUT_IMAGE}:${VULNSCOUT_IMAGE_VERSION}"; then
                    bbfatal "Error: failed to pull the vulnscout image. Please check your Docker setup."
                fi
            fi
            bbplain "No vulnscout container running, creating..."
            ${VULNSCOUT_CONTAINER_ENGINE} run -d --name vulnscout \
                -p 7275:7275 \
                --env-file "${VULNSCOUT_CONFIG_FILE}" \
                -v "${VULNSCOUT_CACHE_DIR}":/cache/vulnscout \
                -v "${VULNSCOUT_DEPLOY_DIR}":/scan/outputs \
                -v "${VULNSCOUT_CONFIG_FILE}":/etc/vulnscout/config.env \
                "${VULNSCOUT_IMAGE}:${VULNSCOUT_IMAGE_VERSION}" daemon
            # Wait for the container process to be ready to accept exec calls
            retries=15
            until ${VULNSCOUT_CONTAINER_ENGINE} exec vulnscout true 2>/dev/null; do
                retries=$(expr "$retries" - 1) || true
                if [ "$retries" -le 0 ]; then
                    bbfatal "Error: container failed to start. Check '${VULNSCOUT_CONTAINER_ENGINE} logs vulnscout'."
                fi
                sleep 1
            done
            break
        else
            mounted_cache=$(${VULNSCOUT_CONTAINER_ENGINE} inspect vulnscout --format '{{range .Mounts}}{{if eq .Destination "/cache/vulnscout"}}{{.Source}}{{end}}{{end}}')
            mounted_outputs=$(${VULNSCOUT_CONTAINER_ENGINE} inspect vulnscout --format '{{range .Mounts}}{{if eq .Destination "/scan/outputs"}}{{.Source}}{{end}}{{end}}')
            mounted_config=$(${VULNSCOUT_CONTAINER_ENGINE} inspect vulnscout --format '{{range .Mounts}}{{if eq .Destination "/etc/vulnscout/config.env"}}{{.Source}}{{end}}{{end}}')
            if [ "$mounted_cache" != "${VULNSCOUT_CACHE_DIR}" ] || \
               [ "$mounted_outputs" != "${VULNSCOUT_DEPLOY_DIR}" ] || \
               [ "$mounted_config" != "${VULNSCOUT_CONFIG_FILE}" ]; then
                bbplain "The existing vulnscout container uses data from another build; recreating it with the current VulnScout directories..."
                counter=$(expr "$counter" + 1)
                if ! ${VULNSCOUT_CONTAINER_ENGINE} rm -f "$containers"; then
                    bbfatal "Error: failed to replace the vulnscout container with the current build configuration."
                fi
                continue
            fi

            # Check if the container is running, if not start it
            docker_status=$(${VULNSCOUT_CONTAINER_ENGINE} inspect vulnscout --format '{{.State.Status}}')
            if [ "$docker_status" != "running" ]; then
                bbplain "Vulnscout container exists but is not running, starting..."
                ${VULNSCOUT_CONTAINER_ENGINE} start vulnscout
                # Wait for the container process to be ready to accept exec calls
                retries=15
                until ${VULNSCOUT_CONTAINER_ENGINE} exec vulnscout true 2>/dev/null; do
                    retries=$(expr "$retries" - 1) || true
                    if [ "$retries" -le 0 ]; then
                        bbfatal "Error: container failed to start. Check '${VULNSCOUT_CONTAINER_ENGINE} logs vulnscout'."
                    fi
                    sleep 1
                done
                break
            fi
            docker_version=$(${VULNSCOUT_CONTAINER_ENGINE} exec vulnscout /scan/src/entrypoint.sh --version)
            if [ "$docker_version" != "${VULNSCOUT_IMAGE_VERSION}" ]; then
                bbplain "A vulnscout container is already running but with an outdated version ($docker_version). Removing it and creating a new one with version ${VULNSCOUT_IMAGE_VERSION}..."
                counter=$(expr "$counter" + 1)
                if ! ${VULNSCOUT_CONTAINER_ENGINE} rm -f "$containers"; then
                    bbfatal "Error: failed to remove existing container with outdated version. Please remove the container named 'vulnscout' and try again."
                fi
            else
                break
            fi
        fi
    done

    if [ $counter -ge 5 ]; then
        bbfatal "Error: failed to create a vulnscout container. Please check your Docker setup and try again."
    fi

    bbplain "Vulnscout Setup Succeed: Docker Env file set at ${VULNSCOUT_CONFIG_FILE}"

}
do_setup_vulnscout[nostamp] = "1"
# Podman needs network access (rootless userns and image pull); BitBake
# isolates tasks otherwise. Docker talks to its daemon and does not.
do_setup_vulnscout[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_setup_vulnscout[doc] = "Configure the env file and create a new container"

do_stop_vulnscout() {
    export PATH="/usr/bin:/usr/sbin:$PATH"
    docker_status=$(${VULNSCOUT_CONTAINER_ENGINE} inspect vulnscout --format '{{.State.Status}}' 2>/dev/null || true)
    if [ "$docker_status" = "running" ]; then
        bbplain "Stopping Vulnscout container..."
        if ! ${VULNSCOUT_CONTAINER_ENGINE} stop vulnscout >/dev/null; then
            bbfatal "Error: failed to stop the vulnscout container."
        fi
    fi
}
do_stop_vulnscout[nostamp] = "1"
do_stop_vulnscout[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_stop_vulnscout[doc] = "Stop the VulnScout Docker container after a normal build"
addtask stop_vulnscout after do_setup_vulnscout before do_build

# Helper function to find files in a directory and its subdirectories based on a pattern
def container_engine(d):
    import os
    # Use host binaries first: the native sysroot ships a non-setuid
    # newuidmap that breaks rootless podman
    os.environ["PATH"] = "/usr/bin:/usr/sbin:" + os.environ.get("PATH", "")
    return d.getVar("VULNSCOUT_CONTAINER_ENGINE")

def find_all(name, path):
    import os
    import fnmatch
    result = []
    for root, dirs, files in os.walk(path):
        for filename in files:
            if fnmatch.fnmatch(filename, f"*{name}*"):
                result.append(os.path.join(root, filename))
    return result

# Helper function to copy the SPDX and CVE-Check files to the container
# Returns the in-container path of the SPDX file and, if it exists, of the
# CVE-Check file (None otherwise)
def copy_sbom_files_to_container(d):
    engine = container_engine(d)
    import subprocess
    import os

    # Retrieve paths for SPDX and CVE-Check files
    spdx_3_path = d.getVar("SPDX_3_PATH")
    spdx_2_path = d.getVar("SPDX_2_PATH")
    cve_check_path = d.getVar("CVE_CHECK_PATH")
    scouted_cve_check_path = d.getVar("SCOUTED_CVE_CHECK_PATH")

    # Determine which SPDX file to use based on INHERIT
    if bb.data.inherits_class("create-spdx-3.0", d):
        spdx_used_path = spdx_3_path
    else:
        spdx_used_path = spdx_2_path

    spdx_real_path = os.path.realpath(spdx_used_path)

    # Determine which CVE-Check file to use
    if os.path.exists(scouted_cve_check_path):
        cve_check_used_path = scouted_cve_check_path
    else:
        cve_check_used_path = cve_check_path

    cve_check_real_path = os.path.realpath(cve_check_used_path)

    # Copy the SPDX into the container
    subprocess.run([engine, 'cp', spdx_real_path, 'vulnscout:/tmp/'], check=True)
    spdx_in_container = f"/tmp/{os.path.basename(spdx_real_path)}"

    # Copy the CVE-Check into the container if it exists
    cve_check_in_container = None
    if os.path.exists(cve_check_real_path):
        subprocess.run([engine, 'cp', cve_check_real_path, 'vulnscout:/tmp/'], check=True)
        cve_check_in_container = f"/tmp/{os.path.basename(cve_check_real_path)}"

    return spdx_in_container, cve_check_in_container

# Helper function to copy reports templates in the container
# If there is not templates on the host, it try anyway
# they may be already present in the container
def copy_reports_to_container(d, reports, folder):
    engine = container_engine(d)
    import subprocess
    import os

    cmd = []

    # Retrieve the templates specified
    templates = []
    for report in reports:
        templates.extend(find_all(report, folder))

    # Copy the templates specified in the container
    for template in templates:
        subprocess.run([engine, 'cp', template, 'vulnscout:/tmp/'], check=True)
        template_in_container = f"/tmp/{os.path.basename(template)}"
        cmd += ['--report', template_in_container]
    # If no template on the host, try the report on the container
    if not templates:
        for report in reports:
            cmd += ['--report', report]
    return cmd

def print_generated_files(files, deploy_dir):
    generated_files = []
    for file in files:
        generated_files.extend(find_all(file, deploy_dir))
    for file in generated_files:
        bb.plain(f"Generated file: {file}")

# Helper function to check if the Vulnscout Flask port is already in use
def check_vulnscout_port(d, port):
    engine = container_engine(d)
    import subprocess

    port_check = subprocess.run(
        [engine, 'exec', 'vulnscout', 'python3', '-c',
         f'import socket; s=socket.socket(); s.settimeout(1); print("in_use" if s.connect_ex(("localhost", {port})) == 0 else "free"); s.close()'],
        capture_output=True, text=True
    )
    if port_check.returncode == 0 and 'in_use' in port_check.stdout:
        bb.warn(f"VulnScout is already serving on port {port} inside the container. "
                f"The web interface may already be accessible at http://localhost:{port}. "
                f"Close the existing session before launching a new one.")
    return False

python do_vulnscout_ci() {
    engine = container_engine(d)
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
        bb.note(
            f"\nLaunching vulnscout in CI mode with match condition set has: " + match_condition + "\n"
            f"Generating scan report " + ", ".join(report_ci) + " Scanning ..." )
    elif match_condition:
        bb.note(f"Launching vulnscout in CI mode with match condition set has: " + match_condition + " Scanning ..." )
    else:
        bb.fatal(f"Launching vulnscout in CI mode without match condition. Please set a match condition.")

    # Launch the vulnscout in CI with the match condition
    cmd = [engine, 'exec', 'vulnscout', '/scan/src/entrypoint.sh', '--project', project, '--variant', variant]
    if match_condition:
        cmd += ['--match-condition', match_condition]
    if report_ci:
        # Copy the custom templates or use the ones in the container
        cmd += copy_reports_to_container(d, report_ci, template_folder)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # Print the logs in the current terminal
    for line in process.stdout:
        bb.plain(line.rstrip())
    process.wait()
    docker_exit_code = process.returncode

    if report_ci:
        print_generated_files(report_ci, output_vulnscout)

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
}
do_vulnscout_ci[nostamp] = "1"
do_vulnscout_ci[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_ci[postfuncs] += "do_stop_vulnscout"
do_vulnscout_ci[doc] = "Launch VulnScout in non-interactive mode. VULNSCOUT_MATCH_CONDITION can be used to test a match condition on the vulnerabilities"
addtask vulnscout_ci after do_setup_vulnscout

python do_vulnscout() {
    engine = container_engine(d)
    import os
    import subprocess

    # Retrieve project and variant information
    variant = d.getVar("VULNSCOUT_VARIANT")
    project = d.getVar("VULNSCOUT_PROJECT")

    # Retrieve paths for SPDX and CVE-Check files
    spdx_3_path = d.getVar("SPDX_3_PATH")
    cve_check_path = d.getVar("CVE_CHECK_PATH")
    scouted_cve_check_path = d.getVar("SCOUTED_CVE_CHECK_PATH")
    sbom_cve_check_spdx3_path = d.getVar("SBOM_CVE_CHECK_SPDX3_PATH")

    port = int(d.getVar("VULNSCOUT_ENV_FLASK_RUN_PORT"))

    # Determine which SPDX file to use based on inherited class
    if bb.data.inherits_class("sbom-cve-check", d):
        spdx_used_path = sbom_cve_check_spdx3_path
    elif bb.data.inherits_class("create-spdx-3.0", d):
        spdx_used_path = spdx_3_path

    spdx_real_path = os.path.realpath(spdx_used_path)

    # Copy the SPDX into the container
    subprocess.run(['docker', 'cp', spdx_real_path, 'vulnscout:/tmp/'], check=True)
    spdx_in_container = f"/tmp/{os.path.basename(spdx_real_path)}"

    # Determine which CVE-Check file to use, if any
    if bb.data.inherits_class("cve-check", d):
        if d.getVarFlag('do_image_improve_kernel_cve_report', 'task'):
            cve_check_used_path = scouted_cve_check_path
        else:
            cve_check_used_path = cve_check_path

        cve_check_real_path = os.path.realpath(cve_check_used_path)

        # Copy the CVE-Check into the container
        subprocess.run(['docker', 'cp', cve_check_real_path, 'vulnscout:/tmp/'], check=True)
        cve_check_in_container = f"/tmp/{os.path.basename(cve_check_real_path)}"
        add_cve_check_in_container = f"--add-cve-check {cve_check_in_container}"
    else:
        add_cve_check_in_container = ""

    # Warn if Flask is already serving inside the container
    check_vulnscout_port(d, port)

    # Check if CVE-Check exist, if yes launch Vulnscout with it
    if cve_check_in_container:
        # Launch Vulnscout in a new terminal and adding the SPDX and CVE-Check files in the database
        cmd = f"{engine} exec vulnscout /scan/src/entrypoint.sh --project {project} --variant {variant} --add-spdx {spdx_in_container} --add-cve-check {cve_check_in_container} --serve ; echo; echo Container exited. Press any key to close...; read x"
        oe_terminal(cmd, "Vulnscout Container Logs", d)
    else:
        # if not launch Vulnscout with only the SPDX file
        cmd = f"{engine} exec vulnscout /scan/src/entrypoint.sh --project {project} --variant {variant} --add-spdx {spdx_in_container} --serve ; echo; echo Container exited. Press any key to close...; read x"
        oe_terminal(cmd, "Vulnscout Container Logs", d)

    oe_terminal(cmd, "Vulnscout Container Logs", d)
}
do_vulnscout[nostamp] = "1"
do_vulnscout[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout[postfuncs] += "do_stop_vulnscout"
do_vulnscout[doc] = "Open a new terminal and launch VulnScout web interface through a Docker container"
addtask vulnscout after do_setup_vulnscout

python do_vulnscout_export() {
    engine = container_engine(d)
    import subprocess

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
    subprocess.run([engine, 'exec', 'vulnscout', '/scan/src/entrypoint.sh'] + cmd_export.split(), check=True)

    print_generated_files(exports, deploy_dir)

}
do_vulnscout_export[nostamp] = "1"
do_vulnscout_export[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_export[postfuncs] += "do_stop_vulnscout"
do_vulnscout_export[doc] = "Generate export files from VulnScout in a Docker container"
addtask vulnscout_export after do_setup_vulnscout

python do_vulnscout_report() {
    engine = container_engine(d)
    import subprocess

    # Retrieve the custom templates, report names and deploy directory
    template_folder = (d.getVar("VULNSCOUT_CUSTOM_TEMPLATES_DIR"))
    reports = (d.getVar("VULNSCOUT_REPORT") or "").split()
    deploy_dir = d.getVar("VULNSCOUT_DEPLOY_DIR")
    cmd_report = ""

    # Call the function to copy the template in the container
    cmd_report = copy_reports_to_container(d, reports, template_folder)

    # Launch the creation of all the reports
    subprocess.run([engine, 'exec', 'vulnscout', '/scan/src/entrypoint.sh'] + cmd_report, check=True)

    print_generated_files(reports, deploy_dir)

}
do_vulnscout_report[nostamp] = "1"
do_vulnscout_report[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_report[postfuncs] += "do_stop_vulnscout"
do_vulnscout_report[doc] = "Generate Vulnscout report files from custom templates"
addtask do_vulnscout_report after do_setup_vulnscout

python do_vulnscout_no_scan(){
    engine = container_engine(d)
    import subprocess

    port = int(d.getVar("VULNSCOUT_ENV_FLASK_RUN_PORT"))

    # Call the function setup_vulnscout
    bb.build.exec_func("do_setup_vulnscout", d)

    # Warn if Flask is already serving inside the container
    check_vulnscout_port(d, port)

    # Launching Vulnscout without scan
    cmd = f"{engine} exec vulnscout /scan/src/entrypoint.sh --serve ; echo; echo Container exited. Press any key to close...; read x"
    oe_terminal(cmd, "Vulnscout Container Logs", d)

}
do_vulnscout_no_scan[nostamp] = "1"
do_vulnscout_no_scan[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_no_scan[postfuncs] += "do_stop_vulnscout"
do_vulnscout_no_scan[doc] = "Open a new terminal and launch VulnScout web interface in a Docker container without any scan"
addtask vulnscout_no_scan
