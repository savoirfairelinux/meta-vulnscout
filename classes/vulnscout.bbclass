# Vulnscout class variables for Yocto Project
VULNSCOUT_ROOT_DIR ?= "${TOPDIR}/.."
VULNSCOUT_DEPLOY_DIR ?= "${VULNSCOUT_ROOT_DIR}/.vulnscout/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}"
VULNSCOUT_CACHE_DIR ?= "${VULNSCOUT_ROOT_DIR}/.vulnscout/cache"

# Repo and version of vulnscout to use
VULNSCOUT_VERSION ?= "v0.8.1"
VULNSCOUT_DOCKER_IMAGE ?= "sflinux/vulnscout"
VULNSCOUT_GIT_URI ?= "https://github.com/savoirfairelinux/vulnscout.git"

# Variables for the vulnscout configuration
VULNSCOUT_ENV_INTERACTIVE_MODE ?= "true"
VULNSCOUT_ENV_FAIL_CONDITION ?= ""
VULNSCOUT_ENV_VERBOSE_MODE ?= "false"
VULNSCOUT_ENV_FLASK_RUN_PORT ?= "7275"
VULNSCOUT_ENV_FLASK_RUN_HOST ?= "0.0.0.0"
VULNSCOUT_ENV_GENERATE_DOCUMENTS ?= "summary.adoc,time_estimates.csv"
VULNSCOUT_ENV_IGNORE_PARSING_ERRORS ?= 'false'

# Enable or disable the kernel CVE improve feature
VULNSCOUT_KERNEL_IMPROVE_CVE ?= "true"

python do_clone_kernel_cve() {
    import subprocess
    import shutil, os
    kernel_improve_cve = d.getVar("VULNSCOUT_KERNEL_IMPROVE_CVE")
    check_spdx = d.getVar("INHERIT")
    rootdir = os.path.join(d.getVar("WORKDIR"), "vulns")

    # Check if the feature is enabled and if SPDX 2.2 is not used
    if kernel_improve_cve == "true" and "create-spdx-2.2" not in check_spdx:
        # Delete previous folder for fetching update
        subprocess.run(['rm', '-rf', rootdir])
        d.setVar("SRC_URI", "git://git.kernel.org/pub/scm/linux/security/vulns.git;branch=master;protocol=https")
        d.setVar("SRCREV", "${AUTOREV}")
        src_uri = (d.getVar('SRC_URI') or "").split()
        # Fetch the kernel vulnerabilities sources
        fetcher = bb.fetch2.Fetch(src_uri, d)
        fetcher.download()
        # Unpack into the standard work directory
        fetcher.unpack(rootdir)

        # Remove the folder ${PN} set by unpack (like core-image-minimal)
        subdirs = [d for d in os.listdir(rootdir) if os.path.isdir(os.path.join(rootdir, d))]
        if len(subdirs) == 1:
            srcdir = os.path.join(rootdir, subdirs[0])
            for f in os.listdir(srcdir):
                shutil.move(os.path.join(srcdir, f), rootdir)
            shutil.rmtree(srcdir)
        bb.plain("Vulnerabilities repo unpacked into: %s" % rootdir)

    elif kernel_improve_cve == "false":
        bb.warn(f"Vulnscout: Kernel enhance CVEs desactivate. cve_check will be incomplete and will miss some vulnerabilities")
    elif "create-spdx-2.2" in check_spdx:
        bb.warn(f"Vulnscout: Kernel enhance CVEs desactivate because SPDX 2.2 is used. cve_check will be incomplete and will miss some vulnerabilities")
}

do_clone_kernel_cve[network] = "1"
do_clone_kernel_cve[nostamp] = "1"
addtask clone_kernel_cve after do_fetch before do_setup_vulnscout

do_setup_vulnscout() {
    # Create a output directory for vulnscout configuration
    mkdir -p ${VULNSCOUT_DEPLOY_DIR}

    # Define Output YAML file
    compose_file="${VULNSCOUT_DEPLOY_DIR}/docker-compose.yml"

    # Add Header section
    cat > "$compose_file" <<EOF
services:
  vulnscout:
    image: ${VULNSCOUT_DOCKER_IMAGE}:${VULNSCOUT_VERSION}
    container_name: vulnscout
    restart: "no"
    ports:
      - "${VULNSCOUT_ENV_FLASK_RUN_PORT}:${VULNSCOUT_ENV_FLASK_RUN_PORT}"
    volumes:
EOF

    # Adding volumes to the docker-compose yml file
    ${@bb.utils.contains('INHERIT', 'cve-check', 'echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json:/scan/inputs/yocto_cve_check/${IMAGE_LINK_NAME}.json:ro,Z" >> $compose_file', '', d)}

    # Test if we use SPDX 3.0 or SPDX 2.2
    if ${@bb.utils.contains('INHERIT', 'create-spdx', 'true', 'false', d)}; then
        echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.json:/scan/inputs/spdx/${IMAGE_LINK_NAME}.spdx.json:ro,Z" >> "$compose_file"
    elif ${@bb.utils.contains('INHERIT', 'create-spdx-2.2', 'true', 'false', d)}; then
        echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.tar.zst:/scan/inputs/spdx/${IMAGE_LINK_NAME}.spdx.tar.zst:ro,Z" >> "$compose_file"
    fi
    ${@bb.utils.contains('INHERIT', 'cyclonedx-export', 'echo "      - ${DEPLOY_DIR}/cyclonedx-export:/scan/inputs/cdx:ro" >> $compose_file', '', d)}
    echo "      - ${VULNSCOUT_DEPLOY_DIR}/output:/scan/outputs:Z" >> "$compose_file"
    echo "      - ${VULNSCOUT_CACHE_DIR}:/cache/vulnscout:Z" >> "$compose_file"

    # Add environnement variables
    cat >> "$compose_file" <<EOF
    environment:
      - FLASK_RUN_PORT=${VULNSCOUT_ENV_FLASK_RUN_PORT}
      - FLASK_RUN_HOST=${VULNSCOUT_ENV_FLASK_RUN_HOST}
      - IGNORE_PARSING_ERRORS=${VULNSCOUT_ENV_IGNORE_PARSING_ERRORS}
      - GENERATE_DOCUMENTS=${VULNSCOUT_ENV_GENERATE_DOCUMENTS}
      - VERBOSE_MODE=${VULNSCOUT_ENV_VERBOSE_MODE}
      - INTERACTIVE_MODE=${VULNSCOUT_ENV_INTERACTIVE_MODE}
EOF

    if [ -n "${VULNSCOUT_ENV_FAIL_CONDITION}" ]; then
        echo "      - FAIL_CONDITION=${VULNSCOUT_ENV_FAIL_CONDITION}" >> "$compose_file"
    fi
    if [ -n "${VULNSCOUT_ENV_PRODUCT_NAME}" ]; then
        echo "      - PRODUCT_NAME=${VULNSCOUT_ENV_PRODUCT_NAME}" >> "$compose_file"
    fi
    if [ -n "${VULNSCOUT_ENV_PRODUCT_VERSION}" ]; then
        echo "      - PRODUCT_VERSION=${VULNSCOUT_ENV_PRODUCT_VERSION}" >> "$compose_file"
    fi
    if [ -n "${VULNSCOUT_ENV_AUTHOR_NAME}" ]; then
        echo "      - AUTHOR_NAME=${VULNSCOUT_ENV_AUTHOR_NAME}" >> "$compose_file"
    fi
    if [ -n "${VULNSCOUT_ENV_CONTACT_EMAIL}" ]; then
        echo "      - CONTACT_EMAIL=${VULNSCOUT_ENV_CONTACT_EMAIL}" >> "$compose_file"
    fi
    if [ -n "${VULNSCOUT_ENV_DOCUMENT_URL}" ]; then
        echo "      - DOCUMENT_URL=${VULNSCOUT_ENV_DOCUMENT_URL}" >> "$compose_file"
    fi
    if [ -n "${NVDCVE_API_KEY}" ]; then
        echo "      - NVD_API_KEY=${NVDCVE_API_KEY}" >> "$compose_file"
    fi

    bbplain "Vulnscout Succeed: Docker Compose file set at ${VULNSCOUT_DEPLOY_DIR}/docker-compose.yml"
    bbplain "Vulnscout Info: Start with the command 'docker-compose -f \"${VULNSCOUT_DEPLOY_DIR}/docker-compose.yml\" up'"

    # Delete do_vulnscout_ci flag
    rm -f "${WORKDIR}/vulnscout_ci_was_run"
}

addtask setup_vulnscout after do_rootfs before do_image

do_enhance_cve_check_with_kernel_vulns() {
    spdx_file="${SPDXIMAGEDEPLOYDIR}/${IMAGE_LINK_NAME}.spdx.json"
    original_cve_check_file="${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json"
    new_cve_report_file="${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}-enhance${IMAGE_NAME_SUFFIX}.json"
    docker_compose_file="${VULNSCOUT_DEPLOY_DIR}/docker-compose.yml"
    improve_kernel_cve_script=$(find ${VULNSCOUT_ROOT_DIR} -name "improve_kernel_cve_report.py")

    if [ "${VULNSCOUT_KERNEL_IMPROVE_CVE}" != "true" ]; then
        bbwarn "Vulnscout: Skipping enhance cve_check with kernel vulnerabilities (VULNSCOUT_KERNEL_IMPROVE_CVE set to false)"
        return 0
    elif ${@bb.utils.contains('INHERIT', 'create-spdx-2.2', 'true', 'false', d)}; then
        bbwarn "Vulnscout: Skipping enhance cve_check with kernel vulnerabilities because SPDX 2.2 is used."
        return 0
    elif [ ! -f "${spdx_file}" ]; then
        bbwarn "Vulnscout: SPDX file not found: ${spdx_file}. Skipping enhance cve_check with kernel vulnerabilities."
        return 0
    elif [ ! -f "${original_cve_check_file}" ]; then
        bbwarn "Vulnscout: CVE_CHECK file not found: ${original_cve_check_file}. Skipping enhance cve_check with kernel vulnerabilities."
        return 0
    fi

    #Launch the new script to improve the cve report
    bbplain "Launching kernel improve cve report script..."
    python3 "${improve_kernel_cve_script}" \
        --spdx "${spdx_file}" \
        --old-cve-report "${original_cve_check_file}" \
        --new-cve-report "${new_cve_report_file}" \
        --datadir "${WORKDIR}/vulns"

    # Replace the old cve report file in the docker-compose file by the new one
    bbplain "Configuring Vulnscout with the new cve report file..."
    sed -i -E "s|^([[:space:]]*)-[[:space:]]*.*/yocto_cve_check/[^:]*\.json:ro,Z|\1- ${new_cve_report_file}:/scan/inputs/yocto_cve_check/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}-enhance${IMAGE_NAME_SUFFIX}.json:ro,Z|" "$docker_compose_file"
}

addtask enhance_cve_check_with_kernel_vulns after do_create_image_spdx before do_create_image_sbom_spdx

python do_vulnscout_ci() {
    import subprocess
    import os

    # Define Output YAML file
    compose_file = d.getVar("VULNSCOUT_DEPLOY_DIR") + "/docker-compose.yml"

    # Deactive the interactive mode in the docker-compose file
    subprocess.run(['sed', '-i', 's/INTERACTIVE_MODE=true/INTERACTIVE_MODE=false/g', compose_file])

    old_fail_condition = d.getVar("VULNSCOUT_ENV_FAIL_CONDITION")
    new_fail_condition = d.getVar("VULS_FAIL_CONDITION",)

    # Chekc if there is a old_fail_condition set up and replace it by the new one
    if new_fail_condition:
        if old_fail_condition:
            subprocess.run(['sed', '-i', 's/FAIL_CONDITION='+ old_fail_condition + '/FAIL_CONDITION= + new_fail_condition + /g', compose_file])
        else:
            subprocess.run(['sed', '-i', "/INTERACTIVE_MODE=false/a \      \- FAIL_CONDITION=" + new_fail_condition, compose_file])
    # If there is not a new_fail_condition and not a old one clean the file
    else:
        if not old_fail_condition:
            subprocess.run(['sed', '-i', '/FAIL_CONDITION=/d', compose_file])

    # Create a flag to inform that do_vulnscout_ci has been run
    open(d.getVar('WORKDIR') + '/vulnscout_ci_was_run', 'w').close()

    # Call the do_vulnscout function
    bb.build.exec_func("do_vulnscout",d)
}

do_vulnscout_ci[nostamp] = "1"
addtask vulnscout_ci after do_setup_vulnscout

python do_vulnscout() {
    import os
    import subprocess
    import shutil
    import re
    import sys
    from os import system

    #Folder variables
    compose_file = d.getVar("VULNSCOUT_DEPLOY_DIR") + "/docker-compose.yml"
    compose_cmd = ""
    log_path = d.getVar("T") + "/log.do_vulnscout_ci"
    output_vulnscout = d.getVar("VULNSCOUT_DEPLOY_DIR") + "/ouput/"

    fail_condition = d.getVar("VULS_FAIL_CONDITION")

    # If there is not a new_fail_condition one, check if there is a old one
    if not fail_condition:
        fail_condition = d.getVar("VULNSCOUT_ENV_FAIL_CONDITION")

    # Check if docker-compose file has been created
    if not os.path.exists(compose_file):
        bb.fatal(f"Cannot start Vulnscout container: {compose_file} does not exist. Run do_setup_vulnscout first.")

    # Check if docker-compose exists on host
    if shutil.which("docker-compose"):
        compose_cmd = "docker-compose"
    else:
        # Check for 'docker compose' subcommand
        try:
            subprocess.run(["docker", "compose", "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            compose_cmd = "docker compose"
        except (subprocess.CalledProcessError, FileNotFoundError):
            bb.fatal("Neither 'docker-compose' nor 'docker compose' are available. Please install one of them.")

    def get_vulnscout_containers():
        # Check if there is already some vulnscout containers and retrieve their IDs
        check_cmd = subprocess.run(['docker', 'ps', '-a', '--filter', 'name=vulnscout','--format', '{{.ID}}'], capture_output=True, text=True)
        containers = check_cmd.stdout.strip().splitlines()
        return containers

    containers = get_vulnscout_containers()
    retry_count = 0
    # If there is already vulnscout containers, delete them. If cannot delete a container, try 5 times then stop.
    while containers:
        bb.plain(f"Found {len(containers)} vulnscout container(s), deleting...")
        success = True
        for cid in containers:
            result = subprocess.run(['docker', 'rm', '-f', cid])
            if result.returncode != 0:
                    bb.war(f"Failed to delete container {cid}: {result.stderr.strip()}")
                    success = False

        if success:
            retry_count = 0
        else:
            retry_count += 1
            if retry_count >= 5:
                bb.fatal("Cannot delete old vulnscout containers. Exiting...")
                break
        # re-check after deletion
        containers = get_vulnscout_containers()

    # Check if vulnscount_ci was run, if so do not open a new shell
    if os.path.exists(d.getVar('WORKDIR') + '/vulnscout_ci_was_run'):
        if fail_condition:
            bb.warn(f"Launching vulnscout in CI mode with fail condition set has: " + fail_condition + " Scanning ..." )
        else:
            bb.warn(f"Launching vulnscout in CI mode without fail condition. Scanning ...")
        subprocess.run(compose_cmd.split() + ['-f', compose_file, 'up'], check=True)

        # Retrieve container status to check if it ended with a error code
        docker_status = subprocess.run(['docker', 'inspect', 'vulnscout', '--format', '{{.State.ExitCode}}'], capture_output=True, text=True)
        docker_exit_code = int(docker_status.stdout.strip())

        # Retrieve all the logs from the container vulnscout
        docker_log = subprocess.run(['docker', 'logs', 'vulnscout'], capture_output=True, text=True)
        docker_result = docker_log.stdout.strip()

        # If the container ended with a error code, stop the code and print it.
        if docker_exit_code == 2:
            bb.fatal(
                f"\n----------------Vulnscout trigger fail condition----------------\n"
                f"----------Trigger condition set : {fail_condition}---------- \n"
                f"{docker_result}"
                f"\n \n ---Vulnscout exit with the code 2 due to fail condition triggered: {fail_condition}---\n"
                f"---Vulnscout has generated multiple files here : {output_vulnscout} ---\n" )
        # Else only show the logs from the container
        else:
            bb.plain("\n----------------Vulnscout scanning----------------")
            if fail_condition:
                bb.plain(f"----------Trigger condition set : {fail_condition}---------- \n")
            else:
                bb.plain("----------Trigger condition not set----------")
            bb.plain(
                f"{docker_result}"
                f"\n---Vulnscout has generated multiple files here : {output_vulnscout} ---\n" )
    else:
        # Use oe_terminal to run in a new interactive shell
        cmd = f"sh -c '{compose_cmd} -f \"{compose_file}\" up; echo \"\\nContainer exited. Press any key to close...\"; read x'"
        oe_terminal(cmd, "Vulnscout Container Logs", d)

    # Stop the container after use
    try:
        subprocess.run(compose_cmd.split() + ["-f", compose_file, "down"], check=True)
    except subprocess.CalledProcessError as e:
        bb.fatal(f"Failed to stop docker-compose: {e}")
}

do_vulnscout[nostamp] = "1"
addtask vulnscout after do_image_complete
