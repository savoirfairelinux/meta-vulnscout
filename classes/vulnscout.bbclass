# Vulnscout class variables for Yocto Project
VULNSCOUT_ROOT_DIR ?= "${TOPDIR}/.."
VULNSCOUT_BASE_DIR ?= "${VULNSCOUT_ROOT_DIR}/.vulnscout"
VULNSCOUT_DEPLOY_DIR ?= "${VULNSCOUT_BASE_DIR}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}"
VULNSCOUT_CACHE_DIR ?= "${VULNSCOUT_BASE_DIR}/cache"
VULNSCOUT_COMPOSE_FILE ?= "${VULNSCOUT_DEPLOY_DIR}/docker-compose.yml"

# Repo and version of vulnscout to use
VULNSCOUT_VERSION ?= "v0.10.0"
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

# Helper function to check if Vulnscout required files are present on the host
check_vulnscout_requirements() {
    SPDX_3_PATH="${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.json"
    SPDX_2_PATH="${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.tar.zst"
    CVE_CHECK_PATH="${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json"
    SCOUTED_CVE_CHECK_PATH="${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.scouted.json"

    # Check the CVE-Check already exist
    if ${@'true' if d.getVarFlag('do_scout_extra_kernel_vulns', 'task') else 'false'}; then
        if [ ! -e "${SCOUTED_CVE_CHECK_PATH}" ]; then
            bbfatal "Scouted CVE-Check file not found at ${SCOUTED_CVE_CHECK_PATH}. Please rebuild the image."
        fi
    elif [ ! -e "${CVE_CHECK_PATH}" ]; then
        bbfatal "CVE-Check file not found at ${CVE_CHECK_PATH}. Please enable 'cve-check' in INHERIT to generate it and rebuild the image."
    fi

    # Check the SPDX-2.2 or SPDX-3.0 files already exist based on INHERIT
    if ${@bb.utils.contains('INHERIT', 'create-spdx-3.0', 'true', 'false', d)}; then
        if [ ! -e "${SPDX_3_PATH}" ]; then
            bbfatal "SPDX-3.0 file not found at ${SPDX_3_PATH}. Please enable 'create-spdx-3.0' in INHERIT to generate it and rebuild the image."
        fi
    elif ${@bb.utils.contains('INHERIT', 'create-spdx', 'true', 'false', d)}; then
        if [ ! -e "${SPDX_2_PATH}" ]; then
            bbfatal "SPDX-2.2 file not found at ${SPDX_2_PATH}. Please enable 'create-spdx' in INHERIT to generate it and rebuild the image."
        fi
    fi
}

do_setup_vulnscout() {
    check_vulnscout_requirements

    # Create a output directory for vulnscout configuration
    mkdir -p ${VULNSCOUT_DEPLOY_DIR}

    if [ ! -e "${VULNSCOUT_BASE_DIR}/.gitignore" ]; then
        cat > "${VULNSCOUT_BASE_DIR}/.gitignore" <<EOF
cache/
EOF
    fi

    # Add Header section
    cat > ${VULNSCOUT_COMPOSE_FILE} <<EOF
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
    if ${@bb.utils.contains('INHERIT', 'cve-check', 'true', 'false', d)}; then
        if ${@'true' if d.getVarFlag('do_scout_extra_kernel_vulns', 'task') else 'false'}; then
            echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.scouted.json:/scan/inputs/yocto_cve_check/${IMAGE_LINK_NAME}.json:ro,Z" >> "${VULNSCOUT_COMPOSE_FILE}"
        else
            echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json:/scan/inputs/yocto_cve_check/${IMAGE_LINK_NAME}.json:ro,Z" >> "${VULNSCOUT_COMPOSE_FILE}"
        fi
    fi

    # Test if we use SPDX 3.* or SPDX 2.2 and older versions
    case "${SPDX_VERSION}" in
        3.*)
            echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.json:/scan/inputs/spdx/${IMAGE_LINK_NAME}.spdx.json:ro,Z" >> "${VULNSCOUT_COMPOSE_FILE}"
            ;;
        *)
            echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.tar.zst:/scan/inputs/spdx/${IMAGE_LINK_NAME}.spdx.tar.zst:ro,Z" >> "${VULNSCOUT_COMPOSE_FILE}"
            ;;
    esac

    ${@bb.utils.contains('INHERIT', 'cyclonedx-export', 'echo "      - ${DEPLOY_DIR}/cyclonedx-export:/scan/inputs/cdx:ro" >> $compose_file', '', d)}
    echo "      - ${VULNSCOUT_DEPLOY_DIR}/output:/scan/outputs:Z" >> "${VULNSCOUT_COMPOSE_FILE}"
    echo "      - ${VULNSCOUT_CACHE_DIR}:/cache/vulnscout:Z" >> "${VULNSCOUT_COMPOSE_FILE}"

    # Add environnement variables
    cat >> ${VULNSCOUT_COMPOSE_FILE} <<EOF
    environment:
      - FLASK_RUN_PORT=${VULNSCOUT_ENV_FLASK_RUN_PORT}
      - FLASK_RUN_HOST=${VULNSCOUT_ENV_FLASK_RUN_HOST}
      - IGNORE_PARSING_ERRORS=${VULNSCOUT_ENV_IGNORE_PARSING_ERRORS}
      - GENERATE_DOCUMENTS=${VULNSCOUT_ENV_GENERATE_DOCUMENTS}
      - VERBOSE_MODE=${VULNSCOUT_ENV_VERBOSE_MODE}
      - INTERACTIVE_MODE=${VULNSCOUT_ENV_INTERACTIVE_MODE}
EOF

    if [ -n "${VULNSCOUT_ENV_FAIL_CONDITION}" ]; then
        echo "      - FAIL_CONDITION=${VULNSCOUT_ENV_FAIL_CONDITION}" >> "${VULNSCOUT_COMPOSE_FILE}"
    fi
    if [ -n "${VULNSCOUT_ENV_PRODUCT_NAME}" ]; then
        echo "      - PRODUCT_NAME=${VULNSCOUT_ENV_PRODUCT_NAME}" >> "${VULNSCOUT_COMPOSE_FILE}"
    fi
    if [ -n "${VULNSCOUT_ENV_PRODUCT_VERSION}" ]; then
        echo "      - PRODUCT_VERSION=${VULNSCOUT_ENV_PRODUCT_VERSION}" >> "${VULNSCOUT_COMPOSE_FILE}"
    fi
    if [ -n "${VULNSCOUT_ENV_AUTHOR_NAME}" ]; then
        echo "      - AUTHOR_NAME=${VULNSCOUT_ENV_AUTHOR_NAME}" >> "${VULNSCOUT_COMPOSE_FILE}"
    fi
    if [ -n "${VULNSCOUT_ENV_CONTACT_EMAIL}" ]; then
        echo "      - CONTACT_EMAIL=${VULNSCOUT_ENV_CONTACT_EMAIL}" >> "${VULNSCOUT_COMPOSE_FILE}"
    fi
    if [ -n "${VULNSCOUT_ENV_DOCUMENT_URL}" ]; then
        echo "      - DOCUMENT_URL=${VULNSCOUT_ENV_DOCUMENT_URL}" >> "${VULNSCOUT_COMPOSE_FILE}"
    fi
    if [ -n "${NVDCVE_API_KEY}" ]; then
        echo "      - NVD_API_KEY=${NVDCVE_API_KEY}" >> "${VULNSCOUT_COMPOSE_FILE}"
    fi

    bbplain "Vulnscout Setup Succeed: Docker Compose file set at ${VULNSCOUT_COMPOSE_FILE}"
    bbplain "Vulnscout Info: After the build you can start web interface with the command 'docker-compose -f ${VULNSCOUT_COMPOSE_FILE} up'"
}
do_setup_vulnscout[doc] = "Configure the yaml file required to start VulnScout in VULNSCOUT_DEPLOY_DIR"
addtask setup_vulnscout after do_scout_extra_kernel_vulns do_image_complete before do_build

python clear_vulnscout_container() {
    import os
    import subprocess
    import shutil
    import re
    import sys

    #Folder variables
    compose_file = d.getVar("VULNSCOUT_COMPOSE_FILE")
    compose_cmd = ""

    # Check if docker-compose file has been created
    if not os.path.exists(compose_file):
        bb.fatal(f"Cannot start Vulnscout container: {compose_file} does not exist. Run do_setup_vulnscout first.")

    # Check if docker-compose exists on host
    if shutil.which("docker-compose"):
        compose_cmd = "docker-compose"
        d.setVar("VULNSCOUT_COMPOSE_CMD",compose_cmd)
    else:
        # Check for 'docker compose' subcommand
        try:
            subprocess.run(["docker", "compose", "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            compose_cmd = "docker compose"
            d.setVar("VULNSCOUT_COMPOSE_CMD",compose_cmd)
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

}

python do_vulnscout_ci() {
    import subprocess
    import os

    # Define Output YAML file
    compose_file = d.getVar("VULNSCOUT_COMPOSE_FILE")

    output_vulnscout = d.getVar("VULNSCOUT_DEPLOY_DIR") + "/output/"

    # Deactive the interactive mode in the docker-compose file
    subprocess.run(['sed', '-i', 's/INTERACTIVE_MODE=true/INTERACTIVE_MODE=false/g', ${VULNSCOUT_COMPOSE_FILE}])

    old_fail_condition = d.getVar("VULNSCOUT_ENV_FAIL_CONDITION")
    new_fail_condition = d.getVar("VULNSCOUT_FAIL_CONDITION",)

    # Chekc if there is a old_fail_condition set up and replace it by the new one
    if new_fail_condition:
        if old_fail_condition:
            subprocess.run(['sed', '-i', 's/FAIL_CONDITION='+ old_fail_condition + '/FAIL_CONDITION= + new_fail_condition + /g', compose_file])
        else:
            subprocess.run(['sed', '-i', "/INTERACTIVE_MODE=false/a \      \- FAIL_CONDITION=" + new_fail_condition, compose_file])
        fail_condition = new_fail_condition
    # If there is not a new_fail_condition and not a old one clean the file
    else:
        if not old_fail_condition:
            subprocess.run(['sed', '-i', '/FAIL_CONDITION=/d', compose_file])
            fail_condition = None
        fail_condition = old_fail_condition

    # Call the do_clear_vulnscout_container function
    bb.build.exec_func("clear_vulnscout_container",d)
    compose_cmd = d.getVar("VULNSCOUT_COMPOSE_CMD")

    # Launch vulnscount_ci
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

    # Stop the container after use
    try:
        subprocess.run(compose_cmd.split() + ["-f", compose_file, "down"], check=True)
    except subprocess.CalledProcessError as e:
        bb.fatal(f"Failed to stop docker-compose: {e}")

}
do_vulnscout_ci[nostamp] = "1"
do_vulnscout_ci[doc] = "Launch VulnScout in non-interactive mode. VULNSCOUT_FAIL_CONDITION can be used to set a fail condition"
addtask vulnscout_ci after do_setup_vulnscout

python do_vulnscout() {
    import os
    import subprocess

    compose_file = d.getVar("VULNSCOUT_COMPOSE_FILE")

    # Call the do_clear_vulnscout_container function
    bb.build.exec_func("clear_vulnscout_container",d)
    compose_cmd = d.getVar("VULNSCOUT_COMPOSE_CMD")

    # Delete fail condition in docker-compose file
    subprocess.run(['sed', '-i', '/FAIL_CONDITION=/d', compose_file])

    # Activate the interactive mode in the docker-compose file
    subprocess.run(['sed', '-i', 's/INTERACTIVE_MODE=false/INTERACTIVE_MODE=true/g', compose_file])

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
do_vulnscout[doc] = "Open a new terminal and launch VulnScout web interface in a Docker container"
addtask vulnscout after do_setup_vulnscout

python do_vulnscout_no_scan(){
    # Call the check_vulnscout_requirements function to check requirements
    # before launching vulnscout
    bb.build.exec_func("check_vulnscout_requirements",d)
    # Call the vulnscout task to start the docker container
    bb.build.exec_func("do_vulnscout",d)
}
do_vulnscout_no_scan[nostamp] = "1"
do_vulnscout_no_scan[doc] = "Open a new terminal and launch VulnScout web interface in a Docker container without scanning the image"
addtask vulnscout_no_scan
