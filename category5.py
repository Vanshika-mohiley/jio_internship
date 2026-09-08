
import csv
import os
import random

CVE_SOURCE_CSV = "category1_final.csv"
SCENARIOS_CSV = "category5_scenarios_template.csv"
OUTPUT_DIR = "category5_scenarios"
GROUND_TRUTH_CSV = "category5_ground_truth.csv"

FILLER_PACKAGES = [
    ("bash", "5.1-6ubuntu1"),
    ("coreutils", "8.32-4.1ubuntu1"),
    ("curl", "7.81.0-1ubuntu1.15"),
    ("openssl", "3.0.2-0ubuntu1.12"),
    ("systemd", "249.11-0ubuntu3.10"),
    ("libc6", "2.35-0ubuntu3.6"),
    ("nginx-common", "1.18.0-6ubuntu14.4"),
    ("python3", "3.10.6-1~22.04"),
    ("openssh-server", "1:8.9p1-3ubuntu0.6"),
    ("vim", "2:8.2.3995-1ubuntu2.15"),
]


def load_cve_lookup(path: str) -> dict:
    """Load your verified Category 1 items, keyed by cve_id, so we can
    pull the exact package/version/description you already confirmed."""
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    return {row["cve_id"]: row for row in rows}


def render_package_list(target_package: str, target_version: str) -> str:
    """A dpkg -l style listing with the target package embedded among
    plausible filler packages, in alphabetical order like a real system
    would show."""
    all_packages = list(FILLER_PACKAGES) + [(target_package, target_version)]
    all_packages.sort(key=lambda p: p[0])

    lines = ["Desired=Unknown/Install/Remove/Purge/Hold",
             "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend",
             "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)",
             "||/ Name           Version                Architecture Description"]
    for name, version in all_packages:
        lines.append(f"ii  {name:<15}{version:<23}amd64        {name} package")
    return "\n".join(lines)


def render_sysctl_note(mitigation_present: str) -> str:
  
    if mitigation_present.strip().lower() == "yes":
        return ("# Relevant hardening settings present on this host:\n"
                "kernel.yama.ptrace_scope = 2\n"
                "fs.suid_dumpable = 0\n")
    else:
        return ("# Relevant hardening settings present on this host:\n"
                "kernel.yama.ptrace_scope = 0\n"
                "fs.suid_dumpable = 1\n")


def render_service_note(service_relevant: str) -> str:
    if service_relevant.strip().lower() == "none":
        return "# No directly relevant service configuration for this scenario.\n"
    if service_relevant.strip().lower() == "sudo":
        return ("# Relevant /etc/sudoers.d/ entry:\n"
                "%admin ALL=(ALL) ALL\n")
    return f"# Relevant service noted: {service_relevant} (add specific config detail manually if needed)\n"


def build_bundle(scenario: dict, cve_row: dict) -> str:
    package = cve_row["package"]
    version = cve_row["installed_version"]

    sections = [
        f"=== SYSTEM SNAPSHOT: {scenario['item_id']} ===\n",
        "--- Installed Packages (dpkg -l excerpt) ---",
        render_package_list(package, version),
        "\n--- Kernel Version (uname -r) ---",
        scenario["kernel_version"],
        "\n--- sysctl (relevant excerpt) ---",
        render_sysctl_note(scenario["sysctl_mitigation_present"]),
        "--- Service Configuration ---",
        render_service_note(scenario["service_relevant"]),
        "\n--- Reference CVE (for your own cross-checking, not shown to the model) ---",
        f"{cve_row['cve_id']}: {cve_row['description'][:200]}",
    ]
    return "\n".join(sections)


def main():
    if not os.path.exists(CVE_SOURCE_CSV):
        print(f"ERROR: {CVE_SOURCE_CSV} not found. Point CVE_SOURCE_CSV at your")
        print("real category1_final30.csv (or category2 equivalent) before running.")
        return

    cve_lookup = load_cve_lookup(CVE_SOURCE_CSV)

    with open(SCENARIOS_CSV, newline="", encoding="utf-8") as f:
        scenarios = list(csv.DictReader(f))

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ground_truth_rows = []

    for scenario in scenarios:
        cve_id = scenario["cve_id"]
        if cve_id not in cve_lookup:
            print(f"WARNING: {cve_id} not found in {CVE_SOURCE_CSV}, skipping {scenario['item_id']}")
            continue

        cve_row = cve_lookup[cve_id]
        bundle_text = build_bundle(scenario, cve_row)

        filepath = os.path.join(OUTPUT_DIR, f"{scenario['item_id']}_bundle.txt")
        with open(filepath, "w", encoding="utf-8") as out:
            out.write(bundle_text)

        ground_truth_rows.append({
            "item_id": scenario["item_id"],
            "bundle_file": filepath,
            "cve_id": cve_id,
            "package": cve_row["package"],
            "installed_version": cve_row["installed_version"],
            "sysctl_mitigation_present": scenario["sysctl_mitigation_present"],
            "service_relevant": scenario["service_relevant"],
            "exploitability_narrative": scenario["exploitability_narrative"],  # YOU write this
            "cis_or_advisory_reference": scenario["cis_or_advisory_reference"],
        })

    if not ground_truth_rows:
        print("No scenarios built -- check that CVE IDs match between the two input files.")
        return

    fieldnames = list(ground_truth_rows[0].keys())
    with open(GROUND_TRUTH_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ground_truth_rows)

    print(f"Generated {len(ground_truth_rows)} scenario bundles in {OUTPUT_DIR}/")
    print(f"Ground truth scaffold written to {GROUND_TRUTH_CSV}")


if __name__ == "__main__":
    main()