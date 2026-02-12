#!/usr/bin/env python3

import argparse
import os
import sys
import json
import re
from typing import Dict, List, Optional

def get_parameters() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kernel CVE filter tool"
    )

    parser.add_argument(
        "--vulns-path",
        required=True,
        help="Path to the kernel vulns repository root"
    )

    parser.add_argument(
        "--input-cve-check",
        required=True,
        help="Path to the cve-check input file"
    )

    parser.add_argument(
        "--input-build-kernel-path",
        required=True,
        help="Path to the kernel source tree"
    )

    parser.add_argument(
        "--output-path-analysis",
        required=True,
        help="Path where kernel_remaining_cves and kernel_removed_cves will be written"
    )

    parser.add_argument(
        "--output-path-cve-check",
        required=True,
        help="Path where the filtered cve-check JSON will be written"
    )

    parser.add_argument(
        "--output-filename-cve-check",
        default="kernel_filtered.json",
        help="Base name for generated output files (default: kernel_filtered.json)"
    )

    parser.add_argument(
        "--output-filename-remaining-cves",
        default="kernel_remaining_cves.json",
        help="Filename for remaining (enabled) kernel CVEs JSON (optional)"
    )

    parser.add_argument(
        "--output-filename-removed-cves",
        default="kernel_removed_cves.json",
        help="Filename for removed kernel CVEs JSON (optional)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="If present, print extra logs details"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.input_build_kernel_path):
        print(f"ERROR: Kernel path is not a directory: {args.input_build_kernel_path}")
        sys.exit(1)

    if not os.path.isfile(args.input_cve_check):
        print(f"ERROR: CVE check input file does not exist: {args.input_cve_check}")
        sys.exit(1)

    if not os.path.isdir(args.vulns_path):
        print(f"ERROR: Vulns path is not a directory: {args.vulns_path}")
        sys.exit(1)
    
    if not os.path.isdir(args.output_path_analysis):
        print(f"ERROR: Output path for analysis results is not a directory: {args.output_path_analysis}")
        sys.exit(1)
    
    if not os.path.isdir(args.output_path_cve_check):
        print(f"ERROR: Output path for CVE check is not a directory: {args.output_path_cve_check}")
        sys.exit(1)

    return args

def vulns_get_affected_files(
    vulns_path: str,
    unfixed_cves: List[Dict[str, Optional[str]]],
    verbose: bool = False
) -> Dict[str, List[str]]:
    """
    For each CVE ID, load its vulns JSON and extract programFiles.
    Returns:
        { cve_id: [file1, file2, ...] }
    """
    results = {}

    for entry in unfixed_cves:
        cve_id = entry.get("id")
        if not cve_id:
            continue

        year = cve_id.split("-")[1]
        cve_file = os.path.join(
            vulns_path,
            "cve",
            "published",
            year,
            f"{cve_id}.json"
        )

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

        affected_files = set()

        affected = (
            data
            .get("containers", {})
            .get("cna", {})
            .get("affected", [])
        )

        for item in affected:
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

def kernel_get_cves_unfixed(path: str) -> List[Dict[str, Optional[str]]]:
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
        pkg_name = pkg.get("name", "")

        if pkg_name != "linux-yocto":
            continue

        for cve in pkg.get("issue", []):
            status = cve.get("status", "").strip()

            if status != "Unpatched":
                continue

            unfixed.append({
                "package": pkg_name,
                "id": cve.get("id"),
                "status": status,
                "summary": cve.get("summary"),
                "link": cve.get("link"),
                "scorev2": cve.get("scorev2"),
                "scorev3": cve.get("scorev3"),
                "scorev4": cve.get("scorev4"),
                "detail": cve.get("detail")
            })

    return unfixed

def kernel_get_compiled_objects(kernel_path: str) -> set[str]:
    """
    Scan kernel build directory and return all .o files relative to kernel root.
    """
    o_files = set()
    for root, dirs, files in os.walk(kernel_path):
        for f in files:
            if f.endswith(".o"):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, kernel_path)
                o_files.add(rel_path)
    return o_files

def kernel_map_cves_to_objects(affected_files_results: dict[str, list[str]], compiled_objects: set[str], enabled_cves: Optional[dict[str, list[str]]] = None) -> None:
    """
    Map CVE affected source files (.c) and headers (.h) to compiled .o files that exist in the kernel build output.
    """
    if enabled_cves is None:
        enabled_cves = {}
    for cve_id, affected_files in affected_files_results.items():
        for f in affected_files:
            if f.endswith(".c") or f.endswith(".h"):
                # Check if any .o file corresponds to this source/header file
                base = os.path.splitext(f)[0]
                possible_o = base + ".o"
                if possible_o in compiled_objects:
                    enabled_cves[cve_id] = affected_files
                    break

def generate_kernel_filtered_cve_check(original_cve_path: str, enabled_cves: Dict[str, List[str]], output_path: str) -> Dict:
    """
    Generate a new cve-check JSON file derived from original_cve_path.
    Instead of removing CVEs, mark kernel CVEs that are NOT enabled as:
        - status = "Ignored"
        - detail = "cve-not-compiled-in-kernel"
    """
    with open(original_cve_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "package" not in data:
        print("ERROR: Invalid CVE check input (missing 'package')")
        sys.exit(1)

    unfixed_entries = kernel_get_cves_unfixed(original_cve_path)
    unfixed_ids = {e["id"] for e in unfixed_entries if e.get("id")}

    if isinstance(enabled_cves, dict):
        enabled_set = set(enabled_cves.keys())
    elif isinstance(enabled_cves, (list, set)):
        enabled_set = set(enabled_cves)
    else:
        enabled_set = set()
    updated_count = 0
    kept_count = 0
    for pkg in data.get("package", []):
        if pkg.get("name") != "linux-yocto":
            continue
        for issue in pkg.get("issue", []):
            iid = issue.get("id")
            if iid in unfixed_ids and iid not in enabled_set:
                # Mark as ignored instead of removing
                issue["status"] = "Ignored"
                issue["detail"] = "cve-not-compiled-in-kernel"
                issue["description"] = "kernel_filter_nonbuilt_cves detected that this CVE is not affecting the current kernel build."
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

def main() -> None:
    args = get_parameters()
    enabled_cves = {}

    # Step 1: Load "Unpatched" CVEs from the input cve-check JSON
    unfixed = kernel_get_cves_unfixed(args.input_cve_check)
    print(f"Unpatched kernel CVEs: {len(unfixed)}")

    # Step 2: For each "Unpatched" CVE, get affected files from vulns repo
    affected_files = vulns_get_affected_files(args.vulns_path, unfixed, args.verbose)
    print(f"CVEs with affected files from vulns repo: {len(affected_files)}")

    # Step 3: Identify CVEs that are "Unpatched" but have no affected files (keep them as active CVE)
    unfixed_ids = {cve["id"] for cve in unfixed if cve.get("id")}
    affected_ids = set(affected_files.keys())
    unmapped_cves = unfixed_ids - affected_ids
    enabled_cves = {cve_id: [] for cve_id in unmapped_cves}
    print(f"CVEs without affected files (keep them as active CVE): {len(unmapped_cves)}")

    # Step 4: Get list of compiled .o files from the kernel build output
    compiled_objects = kernel_get_compiled_objects(args.input_build_kernel_path)
    print(f"Found compiled .o files in the kernel build directory: {len(compiled_objects)}")

    # Step 5: Compare the affected files for each CVE with the compiled objects to determine which CVEs are actually present in the kernel build
    kernel_map_cves_to_objects(affected_files, compiled_objects, enabled_cves)
    print(f"Total CVEs affecting this kernel build: {len(enabled_cves)}")

    # Step 6: Generate output files
    os.makedirs(args.output_path_analysis, exist_ok=True)
    os.makedirs(args.output_path_cve_check, exist_ok=True)

    enabled_cves_path = os.path.join(args.output_path_analysis,f"{args.output_filename_remaining_cves}")
    with open(enabled_cves_path, "w", encoding="utf-8") as f:
        json.dump(enabled_cves, f, indent=4)

    print(f"Wrote active CVEs to: {enabled_cves_path}")

    removed_cves = {k: v for k, v in affected_files.items() if k not in enabled_cves}
    removed_cves_path = os.path.join(args.output_path_analysis,f"{args.output_filename_removed_cves}")
    with open(removed_cves_path, "w", encoding="utf-8") as f:
        json.dump(removed_cves, f, indent=4)

    print(f"Wrote unaffected CVEs to: {removed_cves_path}")

    filtered_path = os.path.join(
        args.output_path_cve_check,
        args.output_filename_cve_check
    )

    generate_kernel_filtered_cve_check(
        args.input_cve_check,
        enabled_cves,
        filtered_path
    )

    print(f"Wrote filtered CVEs to: {filtered_path}")

if __name__ == "__main__":
    main()
