"""
Common artifact schema — every collector (linux/container/windows) normalises
its raw command output into this shape so that downstream modules (CVE
enrichment, LLM engine, report generator) never need to know which OS
produced the data.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Literal, Optional
from pydantic import BaseModel, Field


class Package(BaseModel):
    name: str
    version: str
    architecture: Optional[str] = None
    source: Literal["rpm", "dpkg", "wmic", "container_image"] = "rpm"


class ListeningPort(BaseModel):
    protocol: Literal["tcp", "udp"]
    local_address: str
    local_port: int
    process: Optional[str] = None
    pid: Optional[int] = None


class ServiceUnit(BaseModel):
    name: str
    state: str  # running / stopped / active / inactive etc (raw, normalised later)
    start_type: Optional[str] = None  # enabled/disabled/manual (mostly Windows)


class SUIDBinary(BaseModel):
    path: str
    owner: Optional[str] = None
    permissions: Optional[str] = None


class KernelParam(BaseModel):
    key: str
    value: str


class ContainerInstance(BaseModel):
    id: str
    image: str
    name: Optional[str] = None
    status: Optional[str] = None
    runtime: Literal["docker", "containerd_crictl", "kubernetes_pod"] = "docker"
    namespace: Optional[str] = None  # k8s only


class HostInfo(BaseModel):
    hostname: Optional[str] = None
    os_family: Literal["linux", "windows", "container_host"]
    os_version: Optional[str] = None  # e.g. kernel release / build number
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HotFix(BaseModel):
    """Windows patch (Get-HotFix) — closest analogue to a Linux package update."""
    hotfix_id: str
    description: Optional[str] = None
    installed_on: Optional[str] = None


class CollectionResult(BaseModel):
    """Top-level object each collector script emits as its single JSON output."""
    schema_version: str = "1.0"
    host: HostInfo
    packages: list[Package] = []
    hotfixes: list[HotFix] = []
    listening_ports: list[ListeningPort] = []
    services: list[ServiceUnit] = []
    suid_binaries: list[SUIDBinary] = []
    kernel_params: list[KernelParam] = []
    containers: list[ContainerInstance] = []
    collector_errors: list[str] = []  # non-fatal per-command failures, kept for transparency

    def to_json_file(self, path: str) -> None:
        with open(path, "w") as f:
            f.write(self.model_dump_json(indent=2))
