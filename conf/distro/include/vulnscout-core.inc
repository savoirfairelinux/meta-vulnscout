# Inherit create-spdx to generate SBOMs
# May be required if not using poky distro
INHERIT += "create-spdx"

HOSTTOOLS_NONFATAL += "docker-compose docker"

# Default NVD DB version. The default version use FKIE which is currenctly
# bugged in Yocto with wrong and incomplete CVEs.
NVD_DB_VERSION = "NVD2"
