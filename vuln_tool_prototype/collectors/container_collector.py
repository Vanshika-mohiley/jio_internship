#!/usr/bin/env python3
"""
container_collector.py — inventories running containers/pods on a host,
across the three runtimes commonly found in the field:
  - Docker              (docker ps)
  - containerd/CRI-O     (crictl ps)     — used when Docker is absent (k8s nodes)
  - Kubernetes            (kubectl get pods -o yaml) — cluster-level, if kubeconfig present

Each is optional and independent: a bare Docker host will only populate the
docker branch; a k8s node will typically populate crictl + kubectl.
"""

from __future__ import annotations
import json
import shutil
import subprocess
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from schema.artifact_schema import CollectionResult, HostInfo, ContainerInstance


def run(cmd: list[str], timeout: int = 20) -> tuple[str, str | None]:
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


def collect_docker(result: CollectionResult) -> None:
    if not shutil.which("docker"):
        result.collector_errors.append("docker binary not found — skipping docker collection")
        return
    out, err = run(["docker", "ps", "-a", "--format", "{{json .}}"])
    if err:
        result.collector_errors.append(err)
        return
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        result.containers.append(ContainerInstance(
            id=row.get("ID", ""),
            image=row.get("Image", ""),
            name=row.get("Names"),
            status=row.get("Status"),
            runtime="docker",
        ))


def collect_crictl(result: CollectionResult) -> None:
    if not shutil.which("crictl"):
        result.collector_errors.append("crictl binary not found — skipping containerd/CRI-O collection")
        return
    out, err = run(["crictl", "ps", "-a", "-o", "json"])
    if err:
        result.collector_errors.append(err)
        return
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        result.collector_errors.append("crictl ps returned non-JSON output")
        return
    for c in data.get("containers", []):
        result.containers.append(ContainerInstance(
            id=c.get("id", ""),
            image=c.get("image", {}).get("image", ""),
            name=c.get("metadata", {}).get("name"),
            status=c.get("state"),
            runtime="containerd_crictl",
        ))


def collect_kubectl(result: CollectionResult) -> None:
    if not shutil.which("kubectl"):
        result.collector_errors.append("kubectl binary not found — skipping Kubernetes collection")
        return
    out, err = run(["kubectl", "get", "pods", "--all-namespaces", "-o", "json"], timeout=30)
    if err:
        result.collector_errors.append(err)
        return
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        result.collector_errors.append("kubectl get pods returned non-JSON output")
        return
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        status = item.get("status", {})
        namespace = meta.get("namespace")
        pod_name = meta.get("name")
        for c_status in status.get("containerStatuses", []):
            result.containers.append(ContainerInstance(
                id=c_status.get("containerID", "").replace("containerd://", "").replace("docker://", "")[:12],
                image=c_status.get("image", ""),
                name=f"{pod_name}/{c_status.get('name')}",
                status="running" if c_status.get("state", {}).get("running") else "not_running",
                runtime="kubernetes_pod",
                namespace=namespace,
            ))


def collect() -> CollectionResult:
    hostname = socket.gethostname()
    result = CollectionResult(host=HostInfo(hostname=hostname, os_family="container_host"))
    collect_docker(result)
    collect_crictl(result)
    collect_kubectl(result)
    return result


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "container_artifacts.json"
    result = collect()
    result.to_json_file(out_path)
    print(f"Collected: {len(result.containers)} containers/pods.")
    if result.collector_errors:
        print(f"{len(result.collector_errors)} notes (missing runtimes are normal on a single-runtime host):")
        for e in result.collector_errors:
            print(f"  - {e}")
    print(f"Written to {out_path}")
