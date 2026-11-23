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
VULNSCOUT_IMAGE_VERSION ?= "v0.24"
VULNSCOUT_IMAGE ?= "sflinux/vulnscout"
VULNSCOUT_CONTAINER ?= "vulnscout"

# Variables for the vulnscout configuration
VULNSCOUT_ENV_VERBOSE_MODE ?= "false"
VULNSCOUT_ENV_FLASK_RUN_PORT ?= "7275"
VULNSCOUT_ENV_FLASK_RUN_HOST ?= "0.0.0.0"
VULNSCOUT_ENV_IGNORE_PARSING_ERRORS ?= 'false'
VULNSCOUT_MATCH_CONDITION ?= ""
VULNSCOUT_INPUTS ?= ""
VULNSCOUT_SCANNERS ?= "all"
VULNSCOUT_REPORT_FORMAT ?= ""
VULNSCOUT_EXPORT_AMEND ?= "0"
VULNSCOUT_ALL_VARIANTS ?= "0"
VULNSCOUT_IMPORT_KIND ?= ""
VULNSCOUT_IMPORT_FILE ?= ""
VULNSCOUT_IMPORT_TIMESTAMPS ?= ""
VULNSCOUT_RETARGET_CONTEXT ?= "0"
VULNSCOUT_ASSETS ?= ""
VULNSCOUT_LIST_KIND ?= "projects"
VULNSCOUT_LIST_JSON ?= "0"
VULNSCOUT_CONFIG_ACTION ?= "list"
VULNSCOUT_CONFIG_KEY ?= ""
VULNSCOUT_CONFIG_VALUE ?= ""
VULNSCOUT_DELETE_TARGET ?= ""
VULNSCOUT_DELETE_SCAN_ID ?= ""
VULNSCOUT_DELETE_CONFIRM ?= "0"

# Variable for the Vulnerabilities files
SPDX_3_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.json"
CVE_CHECK_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json"
SCOUTED_CVE_CHECK_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.scouted.json"
SBOM_CVE_CHECK_SPDX3_PATH = "${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}${@d.getVarFlag("SBOM_CVE_CHECK_EXPORT_SPDX3", "ext")}"

python __anonymous() {
    tasks = {
        "add": "Import the image SBOM or explicit inputs",
        "scan": "Run selected vulnerability scanners",
        "match_condition": "Evaluate a policy against stored results",
        "refresh": "Refresh vulnerability data for the image scope",
        "import": "Import assessment data or AI context",
        "asset": "Install report image assets",
        "list": "List projects and variants or scan runs",
        "config": "Read or update persistent VulnScout configuration",
        "delete": "Preview or explicitly apply VulnScout data cleanup",
        "start": "Start the layer's VulnScout container",
        "stop": "Stop the layer's VulnScout container",
        "restart": "Restart the layer's VulnScout container",
        "version": "Show the configured and actual VulnScout version",
        "update": "Pull the configured tag and replace an outdated container",
    }
    for action, description in tasks.items():
        task = f"do_vulnscout_{action}"
        bb.build.addtask(task, "", "", d)
        d.setVarFlag(task, "nostamp", "1")
        d.setVarFlag(task, "doc", description)
    if bb.data.inherits_class("sbom-cve-check", d):
        prerequisite = "do_sbom_cve_check"
    elif bb.data.inherits_class("create-spdx-3.0", d):
        prerequisite = "do_create_image_sbom_spdx"
    else:
        bb.fatal("Neither sbom-cve-check nor create-spdx-3.0 class is inherited. Please inherit one of these classes in your distro config or local.conf.")
    bb.build.addtask("do_setup_vulnscout", "do_build", prerequisite, d)
    if not d.getVar("VULNSCOUT_INPUTS"):
        bb.build.addtask("do_vulnscout_add", "", prerequisite, d)
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

init_vulnscout_config() {
    # Create an output directory for vulnscout configuration
    mkdir -p ${VULNSCOUT_DEPLOY_DIR}

    if [ ! -e "${VULNSCOUT_BASE_DIR}/.gitignore" ]; then
        cat > "${VULNSCOUT_BASE_DIR}/.gitignore" <<EOF
cache/
EOF
    fi

    #  Populate the config file
    if [ ! -f "${VULNSCOUT_CONFIG_FILE}" ]; then
    mkdir -p "${VULNSCOUT_CACHE_DIR}" "$(dirname "${VULNSCOUT_CONFIG_FILE}")"
    (umask 077; cat > "${VULNSCOUT_CONFIG_FILE}") <<EOF
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
}

do_setup_vulnscout() {
    init_vulnscout_config
    counter=0
    while [ $counter -lt 5 ]; do
        containers=$(docker ps -a --filter "name=^/${VULNSCOUT_CONTAINER}$" --format '{{.ID}}') || bbfatal "Cannot access Docker."
        if [ -z "$containers" ]; then
            docker_check_image=$(docker images -q "${VULNSCOUT_IMAGE}:${VULNSCOUT_IMAGE_VERSION}")
            if [ -z "$docker_check_image" ]; then
                bbplain "Pulling vulnscout image ${VULNSCOUT_IMAGE}:${VULNSCOUT_IMAGE_VERSION} from DockerHub..."
                if ! docker pull "${VULNSCOUT_IMAGE}:${VULNSCOUT_IMAGE_VERSION}"; then
                    bbfatal "Error: failed to pull the vulnscout image. Please check your Docker setup."
                fi
            fi
            bbplain "No vulnscout container running, creating..."
            docker run -d --name "${VULNSCOUT_CONTAINER}" \
                -p "127.0.0.1:${VULNSCOUT_ENV_FLASK_RUN_PORT}:${VULNSCOUT_ENV_FLASK_RUN_PORT}" \
                --env-file "${VULNSCOUT_CONFIG_FILE}" \
                -v "${VULNSCOUT_CACHE_DIR}":/cache/vulnscout \
                -v "${VULNSCOUT_DEPLOY_DIR}":/scan/outputs \
                -v "${VULNSCOUT_CONFIG_FILE}":/etc/vulnscout/config.env \
                "${VULNSCOUT_IMAGE}:${VULNSCOUT_IMAGE_VERSION}" daemon || bbfatal "Cannot create the VulnScout container."
            # Wait for the container process to be ready to accept exec calls
            retries=15
            until docker exec "${VULNSCOUT_CONTAINER}" true 2>/dev/null; do
                retries=$(expr "$retries" - 1) || true
                if [ "$retries" -le 0 ]; then
                    bbfatal "Error: container failed to start. Check 'docker logs ${VULNSCOUT_CONTAINER}'."
                fi
                sleep 1
            done
            break
        else
            mounted_cache=$(docker inspect "$containers" --format '{{range .Mounts}}{{if eq .Destination "/cache/vulnscout"}}{{.Source}}{{end}}{{end}}')
            mounted_outputs=$(docker inspect "$containers" --format '{{range .Mounts}}{{if eq .Destination "/scan/outputs"}}{{.Source}}{{end}}{{end}}')
            mounted_config=$(docker inspect "$containers" --format '{{range .Mounts}}{{if eq .Destination "/etc/vulnscout/config.env"}}{{.Source}}{{end}}{{end}}')
            if [ "$mounted_cache" != "$(realpath -m "${VULNSCOUT_CACHE_DIR}")" ]; then
                bbfatal "The name '${VULNSCOUT_CONTAINER}' is already used by a container outside this layer's cache."
            fi
            container_image=$(docker inspect "$containers" --format '{{.Image}}')
            port_bindings=$(docker inspect "$containers" --format '{{json .HostConfig.PortBindings}}')
            requested_image=$(docker image inspect "${VULNSCOUT_IMAGE}:${VULNSCOUT_IMAGE_VERSION}" --format '{{.Id}}' 2>/dev/null || true)
            if [ "$mounted_outputs" != "$(realpath -m "${VULNSCOUT_DEPLOY_DIR}")" ] || \
               [ "$mounted_config" != "$(realpath -m "${VULNSCOUT_CONFIG_FILE}")" ] || \
               [ "$container_image" != "$requested_image" ] || \
               [ "$port_bindings" != '{"${VULNSCOUT_ENV_FLASK_RUN_PORT}/tcp":[{"HostIp":"127.0.0.1","HostPort":"${VULNSCOUT_ENV_FLASK_RUN_PORT}"}]}' ]; then
                bbplain "Recreating the VulnScout container with the current image and mounts..."
                counter=$(expr "$counter" + 1)
                if ! docker rm -f "$containers"; then
                    bbfatal "Error: failed to replace the vulnscout container with the current build configuration."
                fi
                continue
            fi

            # Check if the container is running, if not start it
            docker_status=$(docker inspect "$containers" --format '{{.State.Status}}')
            if [ "$docker_status" != "running" ]; then
                bbplain "Vulnscout container exists but is not running, starting..."
                docker start "$containers" || bbfatal "Cannot start the VulnScout container."
                # Wait for the container process to be ready to accept exec calls
                retries=15
                until docker exec "$containers" true 2>/dev/null; do
                    retries=$(expr "$retries" - 1) || true
                    if [ "$retries" -le 0 ]; then
                        bbfatal "Error: container failed to start. Check 'docker logs ${VULNSCOUT_CONTAINER}'."
                    fi
                    sleep 1
                done
                break
            fi
            break
        fi
    done

    if [ $counter -ge 5 ]; then
        bbfatal "Error: failed to create a vulnscout container. Please check your Docker setup and try again."
    fi

    bbplain "Vulnscout Setup Succeed: Docker Env file set at ${VULNSCOUT_CONFIG_FILE}"

}
do_setup_vulnscout[nostamp] = "1"
do_setup_vulnscout[doc] = "Configure the env file and create a new container"

do_stop_vulnscout() {
    mounted_cache=$(docker inspect "${VULNSCOUT_CONTAINER}" --format '{{range .Mounts}}{{if eq .Destination "/cache/vulnscout"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)
    if [ -n "$mounted_cache" ] && [ "$mounted_cache" != "$(realpath -m "${VULNSCOUT_CACHE_DIR}")" ]; then
        bbfatal "Refusing to stop a VulnScout container belonging to another cache."
    fi
    if [ -z "$mounted_cache" ]; then
        return
    fi
    docker_status=$(docker inspect "${VULNSCOUT_CONTAINER}" --format '{{.State.Status}}' 2>/dev/null || true)
    if [ "$docker_status" = "running" ]; then
        bbplain "Stopping Vulnscout container..."
        if ! docker stop "${VULNSCOUT_CONTAINER}" >/dev/null; then
            bbfatal "Error: failed to stop the vulnscout container."
        fi
    fi
}
do_stop_vulnscout[nostamp] = "1"
do_stop_vulnscout[doc] = "Stop the VulnScout Docker container after a normal build"
addtask stop_vulnscout after do_setup_vulnscout before do_build

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
def vulnscout_reports(reports, folder):
    args = []
    files = []
    for report in reports:
        templates = find_all(report, folder)
        if templates:
            files.extend(("--report", template) for template in templates)
        else:
            args += ["--report", report]
    return args, files

def print_generated_files(files, deploy_dir):
    generated_files = []
    for file in files:
        generated_files.extend(find_all(file, deploy_dir))
    for file in generated_files:
        bb.plain(f"Generated file: {file}")

# Helper function to check if the Vulnscout Flask port is already in use
def check_vulnscout_port(d, port):
    import subprocess

    port_check = subprocess.run(
        ['docker', 'exec', d.getVar("VULNSCOUT_CONTAINER"), 'python3', '-c',
         f'import socket; s=socket.socket(); s.settimeout(1); print("in_use" if s.connect_ex(("localhost", {port})) == 0 else "free"); s.close()'],
        capture_output=True, text=True
    )
    if port_check.returncode == 0 and 'in_use' in port_check.stdout:
        bb.warn(f"VulnScout is already serving on port {port} inside the container. "
                f"The web interface may already be accessible at http://localhost:{port}. "
                f"Close the existing session before launching a new one.")
    return False

python do_vulnscout_ci() {
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
    args, files = vulnscout_reports(report_ci, template_folder)
    vulnscout_exec(d, ["--project", project, "--variant", variant, "--match-condition", match_condition] + args, files, match=True)
    print_generated_files(report_ci, output_vulnscout)
}
do_vulnscout_ci[nostamp] = "1"
do_vulnscout_ci[postfuncs] += "do_stop_vulnscout"
do_vulnscout_ci[doc] = "Launch VulnScout in non-interactive mode. VULNSCOUT_MATCH_CONDITION can be used to test a match condition on the vulnerabilities"
addtask vulnscout_ci

python do_vulnscout() {
    import os
    import shlex
    import subprocess

    bb.build.exec_func("check_vulnscout_requirements", d)

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
    container = d.getVar("VULNSCOUT_CONTAINER")
    subprocess.run(['docker', 'cp', spdx_real_path, f'{container}:/tmp/'], check=True)
    spdx_in_container = f"/tmp/{os.path.basename(spdx_real_path)}"

    # Determine which CVE-Check file to use, if any
    if bb.data.inherits_class("cve-check", d):
        if d.getVarFlag('do_image_improve_kernel_cve_report', 'task'):
            cve_check_used_path = scouted_cve_check_path
        else:
            cve_check_used_path = cve_check_path

        cve_check_real_path = os.path.realpath(cve_check_used_path)

        # Copy the CVE-Check into the container
        subprocess.run(['docker', 'cp', cve_check_real_path, f'{container}:/tmp/'], check=True)
        cve_check_in_container = f"/tmp/{os.path.basename(cve_check_real_path)}"
        add_cve_check_in_container = ["--add-cve-check", cve_check_in_container]
    else:
        add_cve_check_in_container = []

    # Warn if Flask is already serving inside the container
    check_vulnscout_port(d, port)

    # Launch Vulnscout in a new terminal and add the SPDX and CVE-Check (if any)
    # files in the database
    cmd = shlex.join(["docker", "exec", container, "/scan/src/entrypoint.sh",
                      "--project", project, "--variant", variant, "--add-spdx", spdx_in_container]
                     + add_cve_check_in_container + ["--serve"])

    oe_terminal(cmd, "Vulnscout Container Logs", d)
}
do_vulnscout[nostamp] = "1"
do_vulnscout[postfuncs] += "do_stop_vulnscout"
do_vulnscout[doc] = "Open a new terminal and launch VulnScout web interface through a Docker container"
addtask vulnscout after do_setup_vulnscout

python do_vulnscout_export() {
    # Retrieve the export formats and deploy directory
    exports = (d.getVar("VULNSCOUT_EXPORT") or "").split()
    deploy_dir = d.getVar("VULNSCOUT_DEPLOY_DIR")
    formats = {
        "spdx": "spdx", "cdx": "cdx", "openvex": "openvex",
        "custom-data": "custom-vulnscout-data", "custom-openvex": "custom-openvex-assessments",
        "context": "context",
    }
    args = []

    # Check if the export formats are valid
    for export in exports:
        if export not in formats:
            bb.fatal(f"Invalid export format: {export}. Supported formats: {', '.join(formats)}.")
        args.append("--export-" + formats[export])
    if not args:
        bb.fatal("Set VULNSCOUT_EXPORT to at least one format.")
    if d.getVar("VULNSCOUT_EXPORT_AMEND") == "1":
        args.append("--amend")
    all_variants = d.getVar("VULNSCOUT_ALL_VARIANTS") == "1"
    if all_variants:
        if exports != ["custom-openvex"]:
            bb.fatal("VULNSCOUT_ALL_VARIANTS requires a custom-openvex-only export.")
        args.append("--all-variants")

    # Launch the creation of all the export files
    vulnscout_exec(d, vulnscout_scope(d, all_variants) + args)

    print_generated_files(exports, deploy_dir)

}
do_vulnscout_export[nostamp] = "1"
do_vulnscout_export[postfuncs] += "do_stop_vulnscout"
do_vulnscout_export[doc] = "Generate export files from VulnScout in a Docker container"
addtask vulnscout_export

python do_vulnscout_report() {
    # Retrieve the custom templates, report names and deploy directory
    template_folder = (d.getVar("VULNSCOUT_CUSTOM_TEMPLATES_DIR"))
    reports = (d.getVar("VULNSCOUT_REPORT") or "").split()
    deploy_dir = d.getVar("VULNSCOUT_DEPLOY_DIR")
    report_format = d.getVar("VULNSCOUT_REPORT_FORMAT")
    if report_format not in ("", "pdf", "html"):
        bb.fatal("VULNSCOUT_REPORT_FORMAT must be pdf or html.")
    args = vulnscout_scope(d)
    if report_format:
        args += ["--report-format", report_format]

    # Launch the creation of all the reports
    report_args, files = vulnscout_reports(reports, template_folder)
    vulnscout_exec(d, args + report_args, files)

    print_generated_files(reports, deploy_dir)

}
do_vulnscout_report[nostamp] = "1"
do_vulnscout_report[postfuncs] += "do_stop_vulnscout"
do_vulnscout_report[doc] = "Generate Vulnscout report files from custom templates"
addtask do_vulnscout_report

python do_vulnscout_serve() {
    import shlex
    port = int(d.getVar("VULNSCOUT_ENV_FLASK_RUN_PORT"))

    # Call the function setup_vulnscout
    bb.build.exec_func("do_setup_vulnscout", d)

    # Warn if Flask is already serving inside the container
    check_vulnscout_port(d, port)

    # Launching Vulnscout without scan
    cmd = shlex.join(["docker", "exec", d.getVar("VULNSCOUT_CONTAINER"), "/scan/src/entrypoint.sh", "--serve"])
    oe_terminal(cmd, "Vulnscout Container Logs", d)

}
do_vulnscout_serve[nostamp] = "1"
do_vulnscout_serve[postfuncs] += "do_stop_vulnscout"
do_vulnscout_serve[doc] = "Open the VulnScout web interface with existing results"
addtask vulnscout_serve

python do_vulnscout_no_scan() {
    bb.build.exec_func("do_vulnscout_serve", d)
}
do_vulnscout_no_scan[nostamp] = "1"
do_vulnscout_no_scan[postfuncs] += "do_stop_vulnscout"
do_vulnscout_no_scan[doc] = "Open a new terminal and launch VulnScout web interface in a Docker container without any scan"
addtask vulnscout_no_scan

def vulnscout_scope(d, all_variants=False):
    args = ["--project", d.getVar("VULNSCOUT_PROJECT")]
    if not all_variants:
        args += ["--variant", d.getVar("VULNSCOUT_VARIANT")]
    return args

def vulnscout_exec(d, args, files=(), match=False):
    import os
    import subprocess

    for flag, path in files:
        if not os.path.isfile(path):
            bb.fatal(f"Missing VulnScout input for {flag}: {path}")
    bb.build.exec_func("do_setup_vulnscout", d)
    container = d.getVar("VULNSCOUT_CONTAINER")
    docker_exec = ["docker", "exec", container]
    staging = []
    try:
        for flag, path in files:
            directory = subprocess.check_output(docker_exec + ["mktemp", "-d"], text=True).strip()
            staging.append(directory)
            target = f"{directory}/{os.path.basename(path)}"
            subprocess.run(["docker", "cp", os.path.realpath(path), f"{container}:{target}"], check=True)
            args += [flag, target]
        with subprocess.Popen(docker_exec + ["/scan/src/entrypoint.sh"] + args,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
            for line in process.stdout:
                bb.plain(line.rstrip())
            status = process.wait()
    finally:
        if staging:
            subprocess.run(docker_exec + ["rm", "-rf", "--"] + staging, check=False)
    if match and status == 2:
        bb.fatal("VulnScout match condition triggered.")
    if status:
        bb.fatal(f"VulnScout command failed (exit {status}).")

python do_vulnscout_add() {
    import os
    import shlex

    inputs = shlex.split(d.getVar("VULNSCOUT_INPUTS"))
    formats = {"spdx", "cve-check", "yocto-vex", "openvex", "cdx", "grype"}
    files = []
    if inputs:
        for value in inputs:
            kind, separator, path = value.partition("=")
            if not separator or kind not in formats or not path:
                bb.fatal(f"Invalid VULNSCOUT_INPUTS entry: {value}; expected format=path.")
            files.append(("--add-" + kind, path))
    else:
        bb.build.exec_func("check_vulnscout_requirements", d)
        if bb.data.inherits_class("sbom-cve-check", d):
            files.append(("--add-spdx", d.getVar("SBOM_CVE_CHECK_SPDX3_PATH")))
        else:
            files.append(("--add-spdx", d.getVar("SPDX_3_PATH")))
        if bb.data.inherits_class("cve-check", d):
            variable = "SCOUTED_CVE_CHECK_PATH" if d.getVarFlag("do_image_improve_kernel_cve_report", "task") else "CVE_CHECK_PATH"
            cve_path = d.getVar(variable)
            if os.path.isfile(cve_path):
                files.append(("--add-cve-check", cve_path))
    vulnscout_exec(d, vulnscout_scope(d), files)
}

python do_vulnscout_scan() {
    scanners = d.getVar("VULNSCOUT_SCANNERS").replace(",", " ").split()
    if not scanners or set(scanners) - {"all", "grype", "nvd", "osv", "sbom-cve-check"}:
        bb.fatal("VULNSCOUT_SCANNERS must select all, grype, nvd, osv, or sbom-cve-check.")
    vulnscout_exec(d, vulnscout_scope(d) + ["--perform-scans", ",".join(scanners)])
}

python do_vulnscout_match_condition() {
    condition = d.getVar("VULNSCOUT_MATCH_CONDITION")
    if not condition.strip():
        bb.fatal("Set VULNSCOUT_MATCH_CONDITION before evaluating a policy.")
    vulnscout_exec(d, vulnscout_scope(d) + ["--match-condition", condition], match=True)
}

python do_vulnscout_refresh() {
    vulnscout_exec(d, vulnscout_scope(d) + ["--refresh-vulnerability-data"])
}

python do_vulnscout_import() {
    kind = d.getVar("VULNSCOUT_IMPORT_KIND")
    path = d.getVar("VULNSCOUT_IMPORT_FILE")
    formats = {"custom-data": "custom-vulnscout-data", "custom-openvex": "custom-openvex-assessments", "context": "context"}
    if kind not in formats or not path:
        bb.fatal("Set VULNSCOUT_IMPORT_KIND (custom-data, custom-openvex, or context) and VULNSCOUT_IMPORT_FILE.")
    timestamps = d.getVar("VULNSCOUT_IMPORT_TIMESTAMPS")
    all_variants = d.getVar("VULNSCOUT_ALL_VARIANTS") == "1"
    retarget = d.getVar("VULNSCOUT_RETARGET_CONTEXT") == "1"
    args = vulnscout_scope(d, all_variants)
    if timestamps:
        if kind == "context" or timestamps not in ("original", "current"):
            bb.fatal("Use original or current VULNSCOUT_IMPORT_TIMESTAMPS for assessment imports only.")
        args.append(f"--use-{timestamps}-timestamps")
    if all_variants:
        if kind != "custom-openvex":
            bb.fatal("VULNSCOUT_ALL_VARIANTS applies only to custom OpenVEX imports.")
        args.append("--all-variants")
    if retarget:
        if kind != "context":
            bb.fatal("VULNSCOUT_RETARGET_CONTEXT applies only to context imports.")
        args.append("--retarget-context")
    vulnscout_exec(d, args, [("--import-" + formats[kind], path)])
}

python do_vulnscout_asset() {
    import shlex

    assets = shlex.split(d.getVar("VULNSCOUT_ASSETS"))
    if not assets:
        bb.fatal("Set VULNSCOUT_ASSETS to one or more asset paths.")
    vulnscout_exec(d, [], [("--add-asset", path) for path in assets])
}

python do_vulnscout_list() {
    kind = d.getVar("VULNSCOUT_LIST_KIND")
    if kind not in ("projects", "scans"):
        bb.fatal("VULNSCOUT_LIST_KIND must be projects or scans.")
    args = ["--json"] if d.getVar("VULNSCOUT_LIST_JSON") == "1" else []
    vulnscout_exec(d, args + ["--list-" + kind])
}

python do_vulnscout_delete() {
    import uuid

    target = d.getVar("VULNSCOUT_DELETE_TARGET")
    if target not in ("scan", "outdated", "empty-scans", "orphaned-vulns"):
        bb.fatal("Set VULNSCOUT_DELETE_TARGET to scan, outdated, empty-scans, or orphaned-vulns.")
    args = ["--dry-run"] if d.getVar("VULNSCOUT_DELETE_CONFIRM") != "1" else []
    args.append("--delete-" + target)
    if target == "scan":
        try:
            args.append(str(uuid.UUID(d.getVar("VULNSCOUT_DELETE_SCAN_ID"))))
        except ValueError:
            bb.fatal("Set VULNSCOUT_DELETE_SCAN_ID to a valid scan UUID.")
    vulnscout_exec(d, args)
}

def vulnscout_owned_container(d):
    import json
    import os
    import re
    import subprocess

    matches = subprocess.check_output(
        ["docker", "ps", "-aq", "--filter", "name=^/" + re.escape(d.getVar("VULNSCOUT_CONTAINER")) + "$"], text=True
    ).strip()
    if not matches:
        return None
    container = json.loads(subprocess.check_output(["docker", "container", "inspect", matches]))[0]
    cache = os.path.realpath(d.getVar("VULNSCOUT_CACHE_DIR"))
    if not any(mount["Source"] == cache and mount["Destination"] == "/cache/vulnscout"
               for mount in container["Mounts"]):
        bb.fatal("The VulnScout container name is already in use outside this layer's cache.")
    return container

python do_vulnscout_config() {
    import os
    import re
    import subprocess
    import tempfile
    from pathlib import Path

    action = d.getVar("VULNSCOUT_CONFIG_ACTION")
    key = d.getVar("VULNSCOUT_CONFIG_KEY")
    value = d.getVar("VULNSCOUT_CONFIG_VALUE")
    managed = {"FLASK_RUN_PORT", "FLASK_RUN_HOST", "IGNORE_PARSING_ERRORS", "VERBOSE_MODE", "USER_UID", "USER_GID"}
    if action not in ("list", "get", "set", "unset"):
        bb.fatal("VULNSCOUT_CONFIG_ACTION must be list, get, set, or unset.")
    if action != "list" and not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
        bb.fatal("Set VULNSCOUT_CONFIG_KEY to an uppercase environment variable name.")
    if action in ("set", "unset") and key in managed:
        bb.fatal("That key is managed by the layer; configure its BitBake setting instead.")
    if action == "set" and not re.fullmatch(r"[A-Za-z0-9_./:@%+=,?~-]*", value):
        bb.fatal("VULNSCOUT_CONFIG_VALUE must be a plain, shell-safe environment value.")

    bb.build.exec_func("init_vulnscout_config", d)
    path = Path(d.getVar("VULNSCOUT_CONFIG_FILE"))
    lines = path.read_text().splitlines()
    entries = {}
    for line in lines:
        name, separator, current = line.partition("=")
        if separator and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            entries[name] = current
    if action in ("list", "get"):
        if action == "get" and key not in entries:
            bb.fatal(f"VulnScout config key is not set: {key}")
        for name in (entries if action == "list" else [key]):
            if re.search(r"KEY|TOKEN|PASSWORD|PASSWD|SECRET|CREDENTIAL|AUTH|PROXY|URL|DSN", name, re.I):
                bb.plain(f"{name}=****")
            else:
                bb.plain(f"{name}={entries[name]}")
        return

    if (action == "set" and entries.get(key) == value) or (action == "unset" and key not in entries):
        return
    container = vulnscout_owned_container(d)
    lines = [line for line in lines if not line.startswith(f"{key}=")]
    if action == "set":
        lines.append(f"{key}={value}")
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as config:
        try:
            config.write("\n".join(lines) + "\n")
            config.close()
            if container:
                subprocess.run(["docker", "rm", "-f", container["Id"]], check=True)
            os.replace(config.name, path)
        finally:
            if os.path.exists(config.name):
                os.unlink(config.name)
    bb.plain(f"VulnScout config: {action} {key}")
}

python do_vulnscout_start() {
    bb.build.exec_func("do_setup_vulnscout", d)
}

python do_vulnscout_stop() {
    bb.build.exec_func("do_stop_vulnscout", d)
}

python do_vulnscout_restart() {
    bb.build.exec_func("do_stop_vulnscout", d)
    bb.build.exec_func("do_setup_vulnscout", d)
}

python do_vulnscout_version() {
    import subprocess

    image = f'{d.getVar("VULNSCOUT_IMAGE")}:{d.getVar("VULNSCOUT_IMAGE_VERSION")}'
    bb.plain(f"Configured VulnScout image: {image}")
    container = vulnscout_owned_container(d)
    if container:
        version = next((entry.partition("=")[2] for entry in container["Config"]["Env"] or []
                        if entry.startswith("VULNSCOUT_VERSION=")), None)
        if container["State"]["Running"]:
            version = subprocess.check_output(
                ["docker", "exec", container["Id"], "/scan/src/entrypoint.sh", "--version"], text=True
            ).strip()
        bb.plain(f'Container version: {version or container["Config"]["Image"]}')
}

python do_vulnscout_update() {
    import subprocess

    image = f'{d.getVar("VULNSCOUT_IMAGE")}:{d.getVar("VULNSCOUT_IMAGE_VERSION")}'
    container = vulnscout_owned_container(d)
    subprocess.run(["docker", "pull", image], check=True)
    image_id = subprocess.check_output(["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True).strip()
    if container and container["Image"] != image_id:
        bb.build.exec_func("do_setup_vulnscout", d)
        if not container["State"]["Running"]:
            bb.build.exec_func("do_stop_vulnscout", d)
}
