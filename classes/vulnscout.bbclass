# Vulnscout class variables for Yocto Project
VULNSCOUT_ROOT_DIR ?= "${TOPDIR}/.."
VULNSCOUT_DEPLOY_DIR ?= "${VULNSCOUT_ROOT_DIR}/.vulnscout/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}"
VULNSCOUT_CACHE_DIR ?= "${VULNSCOUT_ROOT_DIR}/.vulnscout/cache"

# Repo and version of vulnscout to use
VULNSCOUT_VERSION ?= "v0.7.1"
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
    ${@bb.utils.contains('INHERIT', 'cve-check', 'echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json:/scan/inputs/yocto_cve_check/${IMAGE_LINK_NAME}.json:ro" >> $compose_file', '', d)}

    # Test if we use SPDX 3.0 or SPDX 2.2
    if ${@bb.utils.contains('INHERIT', 'create-spdx', 'true', 'false', d)}; then
        echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.json:/scan/inputs/spdx/${IMAGE_LINK_NAME}.spdx.json:ro" >> "$compose_file"
    elif ${@bb.utils.contains('INHERIT', 'create-spdx-2.2', 'true', 'false', d)}; then
        echo "      - ${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.spdx.tar.zst:/scan/inputs/spdx/${IMAGE_LINK_NAME}.spdx.tar.zst:ro" >> "$compose_file"
    fi
    ${@bb.utils.contains('INHERIT', 'cyclonedx-export', 'echo "      - ${DEPLOY_DIR}/cyclonedx-export:/scan/inputs/cdx:ro" >> $compose_file', '', d)}
    echo "      - ${VULNSCOUT_DEPLOY_DIR}/output:/scan/outputs" >> "$compose_file"
    echo "      - ${VULNSCOUT_CACHE_DIR}:/cache/vulnscout" >> "$compose_file"

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
    if [ -n "${VULNSCOUT_ENV_COMPANY_NAME}" ]; then
        echo "      - COMPANY_NAME=${VULNSCOUT_ENV_COMPANY_NAME}" >> "$compose_file"
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
}

addtask setup_vulnscout after do_rootfs before do_image

python do_vulnscout() {
    import os
    import subprocess
    import shutil

    compose_file = d.getVar("VULNSCOUT_DEPLOY_DIR") + "/docker-compose.yml"
    compose_cmd = ""

    if not os.path.exists(compose_file):
        bb.fatal(f"Cannot start Vulnscout container: {compose_file} does not exist. Run do_vulnscout first.")

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
