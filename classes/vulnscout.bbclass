# Vulnscout class variables for Yocto Project
INPUT_FILES_NAME ?= "${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}"
VULNSCOUT_SCRIPT ?= "${VULNSCOUT_LAYERDIR}/scripts/vulnscout.sh"
VULNSCOUT_ROOT_DIR ?= "${TOPDIR}/.."
VULNSCOUT_DEPLOY_DIR ?= "${VULNSCOUT_ROOT_DIR}/.vulnscout/${INPUT_FILES_NAME}"
VULNSCOUT_DIR ?= "${VULNSCOUT_ROOT_DIR}/.vulnscout"

# Repo and version of vulnscout to use
VULNSCOUT_VERSION ?= "v0.6.0"
DOCKER_IMAGE ?= "sflinux/vulnscout:$VULNSCOUT_VERSION"
VULNSCOUT_GIT_URI ?= "https://github.com/savoirfairelinux/vulnscout.git"

# Variables for the vulnscout configuration
INTERACTIVE_MODE ?= "true"
FAIL_CONDITION ?= ""
VERBOSE_MODE ?= "false"
FLASK_RUN_PORT ?= "7275"
FLASK_RUN_HOST ?= "0.0.0.0"
GENERATE_DOCUMENTS ?= "summary.adoc,time_estimates.csv"
IGNORE_PARSING_ERRORS ?= 'false'

do_vulnscan() {
    # Create a output directory for vulnscout configuration
    mkdir -p ${VULNSCOUT_DEPLOY_DIR}

    # Add vulnscout script to the vulnscout directory
    chmod +x ${VULNSCOUT_SCRIPT}
    install -m 0755 ${VULNSCOUT_SCRIPT} ${VULNSCOUT_DEPLOY_DIR}

    # Create a docker configuration file
    docker_args="-e IGNORE_PARSING_ERRORS=${IGNORE_PARSING_ERRORS-false}"

    if [ -n "${FLASK_RUN_HOST}" ]; then
        docker_args="$docker_args -e FLASK_RUN_HOST=${FLASK_RUN_HOST}"
    fi

    docker_args="$docker_args -e FLASK_RUN_PORT=${FLASK_RUN_PORT-7275}"
    docker_args="$docker_args -p ${FLASK_RUN_PORT-7275}:${FLASK_RUN_PORT-7275}"
    docker_args="$docker_args -e INTERACTIVE_MODE=${INTERACTIVE_MODE}"
    docker_args="$docker_args -e VERBOSE_MODE=${VERBOSE_MODE}"
    docker_args="$docker_args -e GENERATE_DOCUMENTS=\"${GENERATE_DOCUMENTS}\""

    if [ -n "${FAIL_CONDITION}" ]; then
        docker_args="$docker_args -e FAIL_CONDITION=${FAIL_CONDITION}"	
    fi
    if [ -n "${PRODUCT_NAME}" ]; then
        docker_args="$docker_args -e PRODUCT_NAME=${PRODUCT_NAME}"
    fi
    if [ -n "${PRODUCT_VERSION}" ]; then
        docker_args="$docker_args -e PRODUCT_VERSION=${PRODUCT_VERSION}"
    fi
    if [ -n "${COMPANY_NAME}" ]; then
        docker_args="$docker_args -e COMPANY_NAME=${COMPANY_NAME}"
    fi
    if [ -n "${CONTACT_EMAIL}" ]; then
        docker_args="$docker_args -e CONTACT_EMAIL=${CONTACT_EMAIL}"
    fi
    if [ -n "${DOCUMENT_URL}" ]; then
        docker_args="$docker_args -e DOCUMENT_URL=${DOCUMENT_URL}"
    fi

    docker_args="$docker_args -v ${DEPLOY_DIR_IMAGE}/${INPUT_FILES_NAME}.spdx.tar.zst:/scan/inputs/spdx:ro"
    docker_args="$docker_args -v ${DEPLOY_DIR_IMAGE}/${INPUT_FILES_NAME}.rootfs.json:/scan/inputs/yocto_cve_check:ro"
    docker_args="$docker_args ${@bb.utils.contains('INHERIT', 'cyclonedx-export', '-v ${DEPLOY_DIR}/cyclonedx-export:/scan/inputs/cdx:ro', '', d)}"
    docker_args="$docker_args -v ${VULNSCOUT_DEPLOY_DIR}/output:/scan/outputs"
    docker_args="$docker_args -v ${VULNSCOUT_DIR}/cache:/cache/vulnscout"

    echo "$docker_args" > ${VULNSCOUT_DEPLOY_DIR}/docker_args

    bbplain "Vulnscout Succeed: start the vulnscout container with: ${VULNSCOUT_DEPLOY_DIR}/vulnscout.sh"
}

addtask vulnscan after do_rootfs before do_image_complete
