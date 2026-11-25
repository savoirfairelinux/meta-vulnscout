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
VULNSCOUT_SCANNERS ?= "all"

# Set to 0 to not require the image SBOM and CVE-Check files in the setup
VULNSCOUT_CHECK_REQUIREMENTS ?= "1"

# Parameters of the AI assessment and review (the AI provider is configured in
# the VulnScout config file, see the README)
VULNSCOUT_ASSESS_CVES ?= ""
VULNSCOUT_REVIEW_CVES ?= ""
VULNSCOUT_REVIEW_ASSESSMENT_IDS ?= ""
VULNSCOUT_REVIEW_RE_REVIEW ?= "0"
VULNSCOUT_AI_MODEL ?= ""
VULNSCOUT_AI_TIMEOUT ?= ""
VULNSCOUT_AI_DRY_RUN ?= "0"

# Repo and version of vulnscout to use
VULNSCOUT_IMAGE_VERSION ?= "v0.25.1"
VULNSCOUT_IMAGE ?= "sflinux/vulnscout"

# Container engine command: "docker" or "podman"
VULNSCOUT_CONTAINER_ENGINE ?= "docker"

# Variables for the vulnscout configuration
VULNSCOUT_ENV_VERBOSE_MODE ?= "false"
VULNSCOUT_ENV_FLASK_RUN_PORT ?= "7275"
VULNSCOUT_ENV_FLASK_RUN_HOST ?= "0.0.0.0"
VULNSCOUT_ENV_IGNORE_PARSING_ERRORS ?= 'false'
VULNSCOUT_FILTER ?= ""

# Variable for the Vulnerabilities files
SPDX_3_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.json"
SPDX_2_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.tar.zst"
CVE_CHECK_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json"
SCOUTED_CVE_CHECK_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.scouted.json"

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
    if ${@'true' if bb.data.inherits_class("create-spdx-3.0", d) else 'false'}; then
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
    if [ "${VULNSCOUT_CHECK_REQUIREMENTS}" = "1" ]; then
        check_vulnscout_requirements
    fi

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

# Helper function to get the container engine command
def container_engine(d):
    import os
    # Use host binaries first: the native sysroot ships a non-setuid
    # newuidmap that breaks rootless podman
    os.environ["PATH"] = "/usr/bin:/usr/sbin:" + os.environ.get("PATH", "")
    return d.getVar("VULNSCOUT_CONTAINER_ENGINE")

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

# Setup the container for the tasks working on the stored data: they do not
# need the SBOM and CVE-Check files of the image
def vulnscout_setup(d):
    d.setVar("VULNSCOUT_CHECK_REQUIREMENTS", "0")
    bb.build.exec_func("do_setup_vulnscout", d)

# Helper function to run an entrypoint command in the container.
# The output is printed in the BitBake log and the exit code is returned.
def run_vulnscout(d, args):
    import subprocess

    engine = container_engine(d)
    process = subprocess.Popen([engine, 'exec', 'vulnscout', '/scan/src/entrypoint.sh'] + args,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    with process.stdout:
        for line in process.stdout:
            bb.plain(line.rstrip())
    return process.wait()

# Same as run_vulnscout, but any non-zero exit code is fatal
def run_vulnscout_or_fail(d, command, args):
    exit_code = run_vulnscout(d, args)
    if exit_code != 0:
        bb.fatal(f"vulnscout {command} failed with exit code {exit_code}.")

# Project and variant of the current image
def vulnscout_scope_args(d):
    return ['--project', d.getVar("VULNSCOUT_PROJECT"), '--variant', d.getVar("VULNSCOUT_VARIANT")]

# Add the SPDX and CVE-Check files of the image to the VulnScout database
def vulnscout_add(d):
    spdx_in_container, cve_check_in_container = copy_sbom_files_to_container(d)
    args = vulnscout_scope_args(d) + ['--add-spdx', spdx_in_container]
    if cve_check_in_container:
        args += ['--add-cve-check', cve_check_in_container]
    run_vulnscout_or_fail(d, "add", args)

# Open the VulnScout web interface in a new terminal
def vulnscout_serve(d):
    engine = container_engine(d)
    port = int(d.getVar("VULNSCOUT_ENV_FLASK_RUN_PORT"))

    # Warn if Flask is already serving inside the container
    check_vulnscout_port(d, port)

    cmd = f"{engine} exec vulnscout /scan/src/entrypoint.sh --serve ; echo; echo Container exited. Press any key to close...; read x"
    oe_terminal(cmd, "Vulnscout Container Logs", d)

# Generate the reports from the templates found on the host or in the container
def vulnscout_report(d, reports, condition=None):
    template_folder = d.getVar("VULNSCOUT_CUSTOM_TEMPLATES_DIR")
    args = vulnscout_scope_args(d) + copy_reports_to_container(d, reports, template_folder)
    if condition:
        args += ['--match-condition', condition]
    exit_code = run_vulnscout(d, args)
    # With a condition, a match (exit code 2) still means the reports were written
    if exit_code != 0 and not (condition and exit_code == 2):
        bb.fatal(f"vulnscout report failed with exit code {exit_code}.")
    print_generated_files(reports, d.getVar("VULNSCOUT_DEPLOY_DIR"))

# Test the stored vulnerabilities against the match condition
def vulnscout_match_condition(d, condition):
    output_vulnscout = d.getVar("VULNSCOUT_DEPLOY_DIR")
    exit_code = run_vulnscout(d, vulnscout_scope_args(d) + ['--match-condition', condition])

    if exit_code == 2:
        bb.fatal(
            f"\n----------------Vulnscout trigger match_condition----------------\n"
            f"----------Trigger condition set : {condition}---------- \n"
            f"\n---Vulnscout exit with code 2 due to match condition triggered: {condition}---\n"
            f"---Vulnscout has generated multiple files here : {output_vulnscout} ---\n" )
    elif exit_code != 0:
        bb.fatal(f"vulnscout match-condition failed with exit code {exit_code}.")
    bb.plain(
        f"\n---Vulnscout scan completed without triggering match condition: {condition}---\n"
        f"\n---Vulnscout has generated multiple files here : {output_vulnscout} ---\n" )

# Option shared by assess and review
def vulnscout_ai_options(d):
    args = []
    model = d.getVar("VULNSCOUT_AI_MODEL")
    timeout = d.getVar("VULNSCOUT_AI_TIMEOUT")
    if model:
        args += ['--model', model]
    if timeout:
        if not timeout.isdigit() or int(timeout) < 1:
            bb.fatal("VULNSCOUT_AI_TIMEOUT must be a positive number of seconds.")
        args += ['--timeout', timeout]
    if d.getVar("VULNSCOUT_AI_DRY_RUN") == "1":
        args += ['--dry-run']
    return args

python do_vulnscout_add() {
    # Import the SBOM and the CVE-Check of the image
    vulnscout_add(d)
}
do_vulnscout_add[nostamp] = "1"
do_vulnscout_add[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_add[postfuncs] += "do_stop_vulnscout"
do_vulnscout_add[doc] = "Add the SBOM and the CVE-Check of the image to VulnScout, then process them"
addtask vulnscout_add after do_setup_vulnscout

python do_vulnscout_scan() {
    vulnscout_setup(d)
    scanners = (d.getVar("VULNSCOUT_SCANNERS") or "all").replace(",", " ").split()
    valid = ["grype", "nvd", "osv", "sbom-cve-check", "all"]
    for scanner in scanners:
        if scanner not in valid:
            bb.fatal(f"Invalid scanner: {scanner}. Supported scanners are: {', '.join(valid)}.")
    run_vulnscout_or_fail(d, "scan", vulnscout_scope_args(d) + ['--perform-scans', ",".join(scanners)])
}
do_vulnscout_scan[nostamp] = "1"
do_vulnscout_scan[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_scan[postfuncs] += "do_stop_vulnscout"
do_vulnscout_scan[doc] = "Run the vulnerability scanners listed in VULNSCOUT_SCANNERS on the stored data"
addtask vulnscout_scan

python do_vulnscout_refresh() {
    vulnscout_setup(d)
    run_vulnscout_or_fail(d, "refresh", vulnscout_scope_args(d) + ['--refresh-vulnerability-data'])
}
do_vulnscout_refresh[nostamp] = "1"
do_vulnscout_refresh[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_refresh[postfuncs] += "do_stop_vulnscout"
do_vulnscout_refresh[doc] = "Refresh the stored vulnerability data of the image, including EPSS"
addtask vulnscout_refresh

python do_vulnscout_assess() {
    vulnscout_setup(d)
    cves = (d.getVar("VULNSCOUT_ASSESS_CVES") or "").split()
    condition = d.getVar("VULNSCOUT_FILTER")
    if bool(cves) == bool(condition):
        bb.fatal("vulnscout assess needs exactly one of VULNSCOUT_ASSESS_CVES or VULNSCOUT_FILTER.")

    args = ['--project', d.getVar("VULNSCOUT_PROJECT"), '--ai-assess', '--variant', d.getVar("VULNSCOUT_VARIANT")]
    for cve in cves:
        args += ['--cve', cve]
    if condition:
        args += ['--filter', condition]
    run_vulnscout_or_fail(d, "assess", args + vulnscout_ai_options(d))
}
do_vulnscout_assess[nostamp] = "1"
do_vulnscout_assess[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_assess[postfuncs] += "do_stop_vulnscout"
do_vulnscout_assess[doc] = "Assess vulnerabilities with the AI agent. Set VULNSCOUT_ASSESS_CVES or VULNSCOUT_FILTER"
addtask vulnscout_assess

python do_vulnscout_review() {
    vulnscout_setup(d)
    cves = (d.getVar("VULNSCOUT_REVIEW_CVES") or "").split()
    assessment_ids = (d.getVar("VULNSCOUT_REVIEW_ASSESSMENT_IDS") or "").split()
    if bool(cves) == bool(assessment_ids):
        bb.fatal("vulnscout review needs exactly one of VULNSCOUT_REVIEW_CVES or VULNSCOUT_REVIEW_ASSESSMENT_IDS.")

    args = ['--project', d.getVar("VULNSCOUT_PROJECT"), '--ai-review']
    if cves:
        args += ['--variant', d.getVar("VULNSCOUT_VARIANT")]
    for cve in cves:
        args += ['--cve', cve]
    for assessment_id in assessment_ids:
        args += ['--assessment-id', assessment_id]
    if d.getVar("VULNSCOUT_REVIEW_RE_REVIEW") == "1":
        args += ['--re-review']
    run_vulnscout_or_fail(d, "review", args + vulnscout_ai_options(d))
}
do_vulnscout_review[nostamp] = "1"
do_vulnscout_review[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_review[postfuncs] += "do_stop_vulnscout"
do_vulnscout_review[doc] = "Review custom assessments with the AI agent. Set VULNSCOUT_REVIEW_CVES or VULNSCOUT_REVIEW_ASSESSMENT_IDS"
addtask vulnscout_review

python do_vulnscout_match_condition() {
    vulnscout_setup(d)
    condition = d.getVar("VULNSCOUT_FILTER")
    if not condition:
        bb.fatal("vulnscout match-condition needs a match condition. Please set VULNSCOUT_FILTER.")
    vulnscout_match_condition(d, condition)
}
do_vulnscout_match_condition[nostamp] = "1"
do_vulnscout_match_condition[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_match_condition[postfuncs] += "do_stop_vulnscout"
do_vulnscout_match_condition[doc] = "Test the stored vulnerabilities against VULNSCOUT_FILTER. Fails if any vulnerability matches"
addtask vulnscout_match_condition

python do_vulnscout_report() {
    vulnscout_setup(d)
    reports = (d.getVar("VULNSCOUT_REPORT") or "").split()
    vulnscout_report(d, reports)
}
do_vulnscout_report[nostamp] = "1"
do_vulnscout_report[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_report[postfuncs] += "do_stop_vulnscout"
do_vulnscout_report[doc] = "Generate Vulnscout report files from custom templates"
addtask vulnscout_report

python do_vulnscout_export() {
    vulnscout_setup(d)
    # Retrieve the export formats and deploy directory
    exports = (d.getVar("VULNSCOUT_EXPORT") or "").split()
    deploy_dir = d.getVar("VULNSCOUT_DEPLOY_DIR")

    # Check if the export formats are valid
    for export in exports:
        if export not in ["spdx", "cdx", "openvex"]:
            bb.fatal(f"Invalid export format: {export}. Supported formats are: spdx, cdx, openvex.")

    # Launch the creation of all the export files
    cmd_export = vulnscout_scope_args(d)
    for export in exports:
        cmd_export += ['--export-' + export]
    run_vulnscout_or_fail(d, "export", cmd_export)

    print_generated_files(exports, deploy_dir)
}
do_vulnscout_export[nostamp] = "1"
do_vulnscout_export[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_export[postfuncs] += "do_stop_vulnscout"
do_vulnscout_export[doc] = "Generate export files from VulnScout in a Docker container"
addtask vulnscout_export

python do_vulnscout_serve() {
    vulnscout_setup(d)
    vulnscout_serve(d)
}
do_vulnscout_serve[nostamp] = "1"
do_vulnscout_serve[network] = "${@'1' if d.getVar('VULNSCOUT_CONTAINER_ENGINE') == 'podman' else ''}"
do_vulnscout_serve[postfuncs] += "do_stop_vulnscout"
do_vulnscout_serve[doc] = "Open a new terminal and launch the VulnScout web interface on the stored data"
addtask vulnscout_serve
