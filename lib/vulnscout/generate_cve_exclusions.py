#! /usr/bin/env python3

# Generate granular CVE status metadata for a specific version of the kernel
# using json data from cvelistV5 or vulns repository
#
# SPDX-License-Identifier: GPL-2.0-only

import datetime
import json
import os
import glob

from packaging.version import Version

def is_linux_cve(cve_info):
    '''Return true is the CVE belongs to Linux'''
    if not "affected" in cve_info["containers"]["cna"]:
        return False
    for affected in cve_info["containers"]["cna"]["affected"]:
        if not "product" in affected:
            return False
        if affected["product"] == "Linux" and affected["vendor"] == "Linux":
            return True
    return False

def get_fixed_versions(cve_info, base_version):
    '''
    Get fixed versionss
    '''
    first_affected = None
    fixed = None
    fixed_backport = None
    next_version = Version(str(base_version) + ".5000")
    for affected in cve_info["containers"]["cna"]["affected"]:
        # In case the CVE info is not complete, it might not have default status and therefore
        # we don't know the status of this CVE.
        if not "defaultStatus" in affected:
            return first_affected, fixed, fixed_backport
        if affected["defaultStatus"] == "affected":
            for version in affected["versions"]:
                v = Version(version["version"])
                if v == Version('0'):
                    #Skiping non-affected
                    continue
                if version["status"] == "unaffected" and first_affected and v < first_affected:
                    first_affected = Version(f"{v.major}.{v.minor}")
                if version["status"] == "affected" and not first_affected:
                    first_affected = v
                elif (version["status"] == "unaffected" and
                    version['versionType'] == "original_commit_for_fix"):
                    fixed = v
                elif base_version < v and v < next_version:
                    fixed_backport = v
        elif affected["defaultStatus"] == "unaffected":
            # Only specific versions are affected. We care only about our base version
            if "versions" not in affected:
                continue
            for version in affected["versions"]:
                if "versionType" not in version:
                    continue
                if version["versionType"] == "git":
                    continue
                v = Version(version["version"])
                # in case it is not in our base version
                less_than = Version(version["lessThan"])

                if not first_affected:
                    first_affected = v
                fixed = less_than
                if base_version < v and v < next_version:
                    fixed_backport = less_than

    return first_affected, fixed, fixed_backport

def classify_cve(first_affected, fixed, backport_ver, version):
    """
    Classify a single CVE based on version information.
    Returns: { "active": bool, "message": str }
    """
    if not fixed:
        return {"active": True, "message": "no known resolution"}
    if first_affected and version < first_affected:
        return {"active": False, "message": f"fixed-version: only affects {first_affected} onwards"}
    if fixed <= version:
        return {"active": False, "message": f"fixed-version: Fixed from version {fixed}"}
    if backport_ver:
        if backport_ver <= version:
            return {"active": False, "message": f"cpe-stable-backport: Backported in {backport_ver}"}
        return {"active": True, "message": f"May need backporting (fixed from {backport_ver})"}
    return {"active": True, "message": f"Needs backporting (fixed from {fixed})"}

def process_cve_file(cve_file, base_version, version):
    """
    Parse a single CVE JSON file and return (cve_id, status_dict) or None
    if the CVE is not Linux-related or should be skipped.
    """
    cve = cve_file[cve_file.rfind("/") + 1:cve_file.rfind(".json")]
    year = cve.split("-")[1]
    if int(year) < 2015:
        return None

    with open(cve_file, 'r', encoding='utf-8') as f:
        cve_info = json.load(f)

    if not is_linux_cve(cve_info):
        return None

    first_affected, fixed, backport_ver = get_fixed_versions(cve_info, base_version)
    return cve, classify_cve(first_affected, fixed, backport_ver, version)

def generate_cve_exclusions(datadir, version):
    """
    Scan all CVE JSON files in datadir and return a dict of CVE statuses
    for the given kernel version.

    Returns: { cve_id: { "active": bool, "message": str } }
    """
    version = Version(str(version))
    base_version = Version(f"{version.major}.{version.minor}")
    cve_status = {}

    pattern = os.path.join(datadir, '**', "CVE-20*.json")
    for cve_file in sorted(glob.glob(pattern, recursive=True)):
        result = process_cve_file(cve_file, base_version, version)
        if result is not None:
            cve_id, status = result
            cve_status[cve_id] = status

    return cve_status

def write_json_output(cve_status, output_path):
    """Write CVE status dict to a JSON file."""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump({"cve_status": cve_status}, f, indent=2)


def write_inc_output(cve_status, version, output_path):
    """Write CVE status dict to a BitBake .inc file."""
    lines = [f"""
# Auto-generated CVE metadata, DO NOT EDIT BY HAND.
# Generated at {datetime.datetime.now(datetime.timezone.utc)} for kernel version {version}

python check_kernel_cve_status_version() {{
    this_version = "{version}"
    kernel_version = d.getVar("LINUX_VERSION")
    if kernel_version != this_version:
        bb.warn("Kernel CVE status needs updating: generated for %s but kernel is %s" % (this_version, kernel_version))
}}
do_cve_check[prefuncs] += "check_kernel_cve_status_version"
"""]

    for cve, info in cve_status.items():
        if info["active"]:
            lines.append(f'# {cve}: {info["message"]}')
        else:
            lines.append(f'CVE_STATUS[{cve}] = "{info["message"]}"')
        lines.append("")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
