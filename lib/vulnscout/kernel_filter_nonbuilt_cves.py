#!/usr/bin/env python3

import argparse
import os
import sys
import json
import re
from typing import Dict, List, Optional, Set, Tuple

def kernel_parse_o_cmd_file(
    o_cmd_path: str, kernel_root: str
) -> Tuple[Optional[str], Optional[str], Set[str]]:
    """
    Parse a single .o.cmd file and extract:
      - the object file path (relative to kernel_root, from the source_ key)
      - the source .c file path (absolute, as written in the file)
      - the set of .h header paths (absolute, as written in the file)
    """
    obj_file: Optional[str] = None
    src_file: Optional[str] = None
    headers: Set[str] = set()

    try:
        with open(o_cmd_path, "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception as e:
        print(f"WARNING: Failed to read {o_cmd_path}: {e}")
        return None, None, set()

    source_match = re.search(r"^source_(\S+)\s*:=\s*(\S+\.c)", raw, re.MULTILINE)
    if source_match:
        obj_file = source_match.group(1)  # relative to kernel_root
        src_file = source_match.group(2)  # absolute path, kept as-is

    deps_match = re.search(r"^deps_\S+\s*:=\s*(.*)", raw, re.MULTILINE | re.DOTALL)
    if deps_match:
        deps_block = deps_match.group(1)
        deps_flat = deps_block.replace("\\\n", " ")
        for token in deps_flat.split():
            if token.startswith("$("):
                continue  # skip $(wildcard ...) macros
            if not token.endswith(".h"):
                continue
            if os.path.isabs(token):
                headers.add(token)
            else:
                headers.add(os.path.normpath(os.path.join(kernel_root, token)))

    return obj_file, src_file, headers


def kernel_build_compiled_sources(kernel_root: str) -> List[str]:
    """
    Scan the kernel build tree and return the full list of source files
    (.c and .h) referenced across all compiled .o files.
    Returns a sorted list of unique absolute paths as written in the .o.cmd files.
    """
    sources: Set[str] = set()

    for root, _, files in os.walk(kernel_root):
        for filename in files:
            if not filename.endswith(".o.cmd"):
                continue
            o_cmd_path = os.path.join(root, filename)
            _, src_file, headers = kernel_parse_o_cmd_file(o_cmd_path, kernel_root)
            if src_file:
                sources.add(src_file)
            sources.update(headers)

    return sorted(sources)

def kernel_get_unpatched_cves(path: str) -> List[Dict[str, Optional[str]]]:
    """
    Load CVE JSON input and return all CVE entries where status is 'Unpatched'.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "package" not in data:
        print("ERROR: JSON missing 'package' key")
        sys.exit(1)

    unfixed = []
    for pkg in data["package"]:
        if pkg.get("name", "") != "linux-yocto":
            continue
        for cve in pkg.get("issue", []):
            if cve.get("status", "").strip() != "Unpatched":
                continue
            unfixed.append({
                "package": pkg.get("name"),
                "id": cve.get("id"),
                "status": cve.get("status"),
                "summary": cve.get("summary"),
                "link": cve.get("link"),
                "scorev2": cve.get("scorev2"),
                "scorev3": cve.get("scorev3"),
                "scorev4": cve.get("scorev4"),
                "detail": cve.get("detail"),
            })

    return unfixed


def kernel_get_cve_program_files(
    vulns_path: str,
    unfixed_cves: List[Dict[str, Optional[str]]],
    verbose: bool = False,
) -> Dict[str, List[str]]:
    """
    For each CVE ID, load its vulns JSON and extract programFiles.
    Returns: { cve_id: [file1, file2, ...] }
    """
    results = {}

    for entry in unfixed_cves:
        cve_id = entry.get("id")
        if not cve_id:
            continue

        year = cve_id.split("-")[1]
        cve_file = os.path.join(vulns_path, "cve", "published", year, f"{cve_id}.json")

        if not os.path.isfile(cve_file):
            if verbose:
                print(f"WARNING: Missing vulns entry for {cve_id}")
            continue

        try:
            with open(cve_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            if verbose:
                print(f"ERROR: Failed parsing {cve_file}: {e}")
            continue

        affected_files: Set[str] = set()
        for item in data.get("containers", {}).get("cna", {}).get("affected", []):
            if item.get("product") != "Linux":
                continue
            for f in item.get("programFiles", []):
                affected_files.add(f)

        if affected_files:
            results[cve_id] = sorted(affected_files)
            if verbose:
                print(f"{cve_id}:")
                for f in affected_files:
                    print(f"  - {f}")

    return results

def kernel_filter_cves_by_compiled_sources(
    affected_files_by_cve: Dict[str, List[str]],
    compiled_sources: List[str],
    enabled_cves: Optional[Dict[str, List[str]]] = None,
) -> None:
    """
    For each CVE, check whether any of its programFiles (.c or .h) appears
    as a suffix of any path in compiled_sources (the .o.cmd-derived set).
    If so, the CVE is considered active in this kernel build.
    """
    if enabled_cves is None:
        enabled_cves = {}

    # Build a set of all compiled source basenames for fast suffix matching
    compiled_set = set(compiled_sources)

    for cve_id, affected_files in affected_files_by_cve.items():
        for f in affected_files:
            if not (f.endswith(".c") or f.endswith(".h")):
                continue
            # A programFile like "lib/lz4/lz4_decompress.c" should match
            # any compiled source whose absolute path ends with that suffix.
            if any(src.endswith(f) for src in compiled_set):
                enabled_cves[cve_id] = affected_files
                break

def generate_kernel_filtered_cve_check(
    original_cve_path: str,
    enabled_cves: Dict[str, List[str]],
    output_path: str,
) -> Dict:
    """
    Generate a filtered cve-check JSON. Kernel CVEs that are Unpatched but
    NOT in enabled_cves are marked as Ignored with detail 'cve-not-compiled-in-kernel'.
    """
    with open(original_cve_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "package" not in data:
        print("ERROR: Invalid CVE check input (missing 'package')")
        sys.exit(1)
    unfixed_ids = {e["id"] for e in kernel_get_unpatched_cves(original_cve_path) if e.get("id")}
    enabled_set = set(enabled_cves.keys()) if isinstance(enabled_cves, dict) else set(enabled_cves)
    updated_count = 0
    kept_count = 0
    for pkg in data.get("package", []):
        if pkg.get("name") != "linux-yocto":
            continue
        for issue in pkg.get("issue", []):
            iid = issue.get("id")
            if iid in unfixed_ids and iid not in enabled_set:
                issue["status"] = "Ignored"
                issue["detail"] = "cve-not-compiled-in-kernel"
                issue["description"] = (
                    "kernel_filter_nonbuilt_cves detected that this CVE "
                    "is not affecting the current kernel build."
                )
                updated_count += 1
            elif iid in unfixed_ids:
                kept_count += 1
    try:
        with open(output_path, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=4)
        print(f"Wrote filtered rootfs CVE report to: {output_path}")
        print(f"Kernel CVEs ignored: {updated_count}, kept as Unpatched: {kept_count}")
    except Exception as e:
        print(f"ERROR: Failed writing {output_path}: {e}")
        sys.exit(1)
    return data
