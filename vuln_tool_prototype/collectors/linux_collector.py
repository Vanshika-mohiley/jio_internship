#!/usr/bin/env python3
"""
linux_collector.py — gathers OS-level security-relevant artefacts from a
local Linux host and normalises them into the common CollectionResult schema.

Commands used (all read-only, no data leaves the machine):
  - rpm -qa            (RHEL/Fedora/SUSE package inventory)
  - dpkg -l             (Debian/Ubuntu package inventory)
  - uname -r            (kernel version)
  - sysctl -a           (kernel parameters)
  - ss -tlnp            (listening TCP ports + owning process)
  - systemctl list-units --type=service (service inventory)
  - find / -perm -4000  (SUID binaries)

Each command is wrapped individually — if one fails (missing binary, no
permission) we record the error in collector_errors and continue, rather
than aborting the whole collection run.
"""

from __future__ import annotations
import subprocess
import socket
import sys
import os
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from schema.artifact_schema import (
    CollectionResult, HostInfo, Package, ListeningPort,
    ServiceUnit, SUIDBinary, KernelParam,
)


def run(cmd: list[str], timeout: int = 30) -> tuple[str, Optional[str]]:
    """Run a command, return (stdout, error). Never raises."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0 and not proc.stdout:
            return "", f"{' '.join(cmd)} exited {proc.returncode}: {proc.stderr.strip()[:200]}"
        return proc.stdout, None
    except FileNotFoundError:
        return "", f"{cmd[0]} not found on this system"
    except subprocess.TimeoutExpired:
        return "", f"{' '.join(cmd)} timed out after {timeout}s"
    except Exception as e:
        return "", f"{' '.join(cmd)} failed: {e}"


def collect_kernel_version(result: CollectionResult) -> None:
    out, err = run(["uname", "-r"])
    if err:
        result.collector_errors.append(err)
    else:
        result.host.os_version = out.strip()


def collect_packages_rpm(result: CollectionResult) -> None:
    out, err = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"])
    if err:
        result.collector_errors.append(err)
        return
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            name, version, arch = parts
            result.packages.append(Package(name=name, version=version, architecture=arch, source="rpm"))


def collect_packages_dpkg(result: CollectionResult) -> None:
    out, err = run(["dpkg", "-l"])
    if err:
        result.collector_errors.append(err)
        return
    for line in out.splitlines():
        if not line.startswith("ii"):
            continue
        fields = line.split()
        if len(fields) >= 4:
            _, name, version, arch = fields[0], fields[1], fields[2], fields[3]
            result.packages.append(Package(name=name, version=version, architecture=arch, source="dpkg"))


def collect_sysctl(result: CollectionResult) -> None:
    out, err = run(["sysctl", "-a"])
    if err:
        result.collector_errors.append(err)
        return
    for line in out.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        result.kernel_params.append(KernelParam(key=key.strip(), value=value.strip()))


def collect_listening_ports(result: CollectionResult) -> None:
    # ss -tlnp needs root for process/pid info; falls back gracefully without it
    out, err = run(["ss", "-tlnp"])
    if err:
        result.collector_errors.append(err)
        return
    for line in out.splitlines()[1:]:  # skip header
        fields = line.split()
        if len(fields) < 4:
            continue
        proto = "tcp"
        local = fields[3]
        if ":" not in local:
            continue
        addr, _, port = local.rpartition(":")
        try:
            port_num = int(port)
        except ValueError:
            continue
        process = None
        pid = None
        if len(fields) >= 6 and "pid=" in fields[-1]:
            proc_field = fields[-1]
            try:
                pid = int(proc_field.split("pid=")[1].split(",")[0])
                process = proc_field.split('"')[1] if '"' in proc_field else None
            except (IndexError, ValueError):
                pass
        result.listening_ports.append(
            ListeningPort(protocol=proto, local_address=addr, local_port=port_num, process=process, pid=pid)
        )


def collect_services(result: CollectionResult) -> None:
    out, err = run(["systemctl", "list-units", "--type=service", "--no-pager", "--no-legend"])
    if err:
        result.collector_errors.append(err)
        return
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            name = fields[0]
            active_state = fields[2]  # active/inactive/failed
            result.services.append(ServiceUnit(name=name, state=active_state))


def collect_suid_binaries(result: CollectionResult, search_root: str = "/") -> None:
    out, err = run(["find", search_root, "-xdev", "-perm", "-4000", "-type", "f"], timeout=60)
    if err:
        result.collector_errors.append(err)
        return
    for path in out.splitlines():
        path = path.strip()
        if not path:
            continue
        owner = None
        perms = None
        try:
            st = os.stat(path)
            import stat as stat_module
            import pwd
            owner = pwd.getpwuid(st.st_uid).pw_name
            perms = stat_module.filemode(st.st_mode)
        except Exception:
            pass
        result.suid_binaries.append(SUIDBinary(path=path, owner=owner, permissions=perms))


def collect() -> CollectionResult:
    hostname = socket.gethostname()
    result = CollectionResult(host=HostInfo(hostname=hostname, os_family="linux"))

    collect_kernel_version(result)
    collect_packages_rpm(result)
    collect_packages_dpkg(result)
    collect_sysctl(result)
    collect_listening_ports(result)
    collect_services(result)
    collect_suid_binaries(result)

    return result


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "linux_artifacts.json"
    result = collect()
    result.to_json_file(out_path)
    print(f"Collected: {len(result.packages)} packages, {len(result.listening_ports)} listening ports, "
          f"{len(result.services)} services, {len(result.suid_binaries)} SUID binaries, "
          f"{len(result.kernel_params)} kernel params.")
    if result.collector_errors:
        print(f"{len(result.collector_errors)} non-fatal errors (see collector_errors in output JSON):")
        for e in result.collector_errors:
            print(f"  - {e}")
    print(f"Written to {out_path}")
