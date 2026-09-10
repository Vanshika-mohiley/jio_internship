"""
prompt_builder.py — Day 3 deliverable. Builds chain-of-thought prompts that
inject (a) raw artefact data from the collectors and (b) RAG-retrieved CVE
context from retrieval.py, and instruct the local LLM to reason step by
step before emitting a single structured JSON object matching
schema.findings_schema.FindingsList.

Two prompt types, kept separate because they reason over different evidence:
  - build_package_prompt():     CVE-driven findings for a single package
                                  that already has exact/semantic CVE hits.
  - build_host_config_prompt(): configuration-driven findings (open ports,
                                  SUID binaries, risky kernel params, running
                                  services) that have no CVE ID at all.

Both end with the same strict output-format instruction so llm_engine.py
can parse either response the same way.
"""

from __future__ import annotations
import json


OUTPUT_FORMAT_INSTRUCTIONS = """
1. Only report facts that are explicitly supported by the supplied artifacts or
   enrichment evidence.

2. NEVER associate an installed package with a listening port, service, or
   process unless the artifact explicitly identifies that package/process as
   owning that port or service.

3. A listening port with process=null is evidence only that a port is listening.
   It is NOT evidence that any particular installed package is responsible.

4. Do not infer that Git, Python, Java, or any other installed software is
   listening on a port merely because the software is installed.

5. Candidate CVE matches are NOT confirmed vulnerabilities. Only report a CVE
   when the supplied evidence establishes that the affected product and
   affected version actually match the installed component.

6. If evidence is insufficient, do not create a finding.

7. Configuration/exposure findings must be described as configuration or
   exposure issues, not as CVE vulnerabilities unless a CVE is explicitly
   supported by the evidence.

8. For every finding, the affected_component must correspond to a component
   explicitly present in the supplied evidence.

9. Respond with ONLY a single JSON object, no prose before or after it, no
markdown code fences. It must match this exact shape:

{
  "findings": [
    {
      "title": "short one-line summary",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
      "affected_component": "package or service name",
      "installed_version": "version string or null",
      "cve_ids": ["CVE-YYYY-NNNNN", ...],
      "description": "2-4 sentences on what the issue is and why it matters",
      "remediation": "concrete, specific fix",
      "confidence": "exact" | "semantic" | "heuristic"
    }
  ]
}

If you find nothing actionable, return {"findings": []}. Do not invent
CVE IDs that were not provided to you in the context below.
""".strip()


def build_package_prompt(package_name: str, installed_version: str, enrichment: dict) -> str:
    """
    enrichment is the dict returned by retrieval.enrich_package(): contains
    exact_matches (advisory-sourced) and/or semantic_matches (NVD RAG hits).
    """
    if enrichment["exact_matches"]:
        evidence_block = "Vendor security advisory matches (high confidence — these versions are confirmed fixes):\n"
        for m in enrichment["exact_matches"]:
            evidence_block += (
                f"  - {m['cve_id']}: fixed in {m['package_name']} {m['fixed_version']} "
                f"({m['distro']}, source: {m['source']})\n"
            )
        confidence_hint = "exact"
    else:
        evidence_block = "Semantically similar CVEs retrieved from the local NVD index (lower confidence — verify relevance):\n"
        for m in enrichment["semantic_matches"]:
            evidence_block += (
                f"  - {m['cve_id']} (CVSS {m['cvss_v3_score']}, {m['cvss_v3_severity']}): {m['description']}\n"
            )
        confidence_hint = "semantic"

    prompt = f"""
You are a vulnerability analyst reviewing a single installed package on a host.

Package: {package_name}
Installed version: {installed_version}

{evidence_block}

Think step by step before answering:
1. Does the evidence above genuinely apply to this exact package and version, or could it be a false positive (e.g. a similarly-named but unrelated package, or a version that already includes the fix)?
2. If it applies, how severe is it in a typical deployment (consider exploitability, and whether the vulnerable component is usually exposed)?
3. What is the precise, actionable remediation (exact version to upgrade to, or config change)?

Only emit a finding if you are reasonably confident it is a real issue for this exact package/version. Use confidence="{confidence_hint}" unless your own reasoning changes that judgment.

{OUTPUT_FORMAT_INSTRUCTIONS}
""".strip()
    return prompt


def build_host_config_prompt(
    hostname: str,
    os_family: str,
    listening_ports: list,
    suid_binaries: list,
    services: list,
    kernel_params: list,
) -> str:
    """
    Configuration/hardening findings that don't map to a specific CVE —
    e.g. an unnecessary listening port, an unusual SUID binary, a risky
    sysctl value, or a service that shouldn't be running on a hardened host.
    Kernel params are pre-filtered by the caller to a security-relevant
    subset (see llm_engine.SECURITY_RELEVANT_SYSCTL_KEYS) — sending all ~800
    raw sysctl keys would blow the context window for no benefit.
    """
    ports_block = "\n".join(
        f"  - {p.protocol}/{p.local_port} ({p.local_address}) process={p.process or 'unknown'}"
        for p in listening_ports
    ) or "  (none reported)"

    suid_block = "\n".join(
        f"  - {s.path} owner={s.owner or 'unknown'} perms={s.permissions or 'unknown'}"
        for s in suid_binaries
    ) or "  (none reported)"

    services_block = "\n".join(
        f"  - {s.name}: {s.state}" for s in services if s.state.lower() in ("running", "active")
    ) or "  (none reported / none active)"

    kernel_block = "\n".join(f"  - {k.key} = {k.value}" for k in kernel_params) or "  (none flagged)"

    prompt = f"""
You are a system-hardening analyst reviewing host configuration for security issues that are NOT tied to a specific CVE (e.g. exposed services, unusual SUID binaries, risky kernel parameters).

Host: {hostname} ({os_family})

Listening network ports:
{ports_block}

SUID binaries found on disk:
{suid_block}

Active services:
{services_block}

Security-relevant kernel parameters:
{kernel_block}

Think step by step before answering:
1. Are any listening ports unusual, unnecessary, or commonly associated with lateral movement / remote access risk for this kind of host?
2. Are any SUID binaries non-standard (i.e. not the usual sudo/passwd/ping-type system binaries) — these are common privilege-escalation vectors?
3. Do any kernel parameters weaken standard hardening baselines (e.g. IP forwarding enabled unexpectedly, ASLR disabled, core dumps enabled)?

Only flag things a competent sysadmin would actually act on — do not flag standard, expected services or default-safe kernel values just to pad the list. Use confidence="heuristic" for all findings from this analysis, since none are CVE-backed.

{OUTPUT_FORMAT_INSTRUCTIONS}
""".strip()
    return prompt

def build_assessment_prompt(collection: dict, enrichment: dict) -> str:
    """Build one bounded prompt from Windows artifacts plus local CVE evidence.

    The current Windows assessment path combines package/CVE evidence with
    host-configuration evidence (especially externally bound listening ports
    and running services). Candidate product-name CVE matches remain
    explicitly non-confirmed and must never be promoted to vulnerabilities.
    """
    host = collection.get("host", {}) if isinstance(collection, dict) else {}
    packages = collection.get("packages", []) if isinstance(collection, dict) else []
    ports = collection.get("listening_ports", []) if isinstance(collection, dict) else []
    services = collection.get("services", []) if isinstance(collection, dict) else []
    suid_binaries = collection.get("suid_binaries", []) if isinstance(collection, dict) else []
    kernel_params = collection.get("kernel_params", []) if isinstance(collection, dict) else []
    matches = enrichment.get("matches", []) if isinstance(enrichment, dict) else []

    package_lines = []
    for p in packages[:100]:
        if isinstance(p, dict):
            package_lines.append(
                f"  - {p.get('name', 'unknown')} {p.get('version', 'unknown')} "
                f"({p.get('source', 'unknown')})"
            )

    evidence_lines = []
    for m in matches[:50]:
        if not isinstance(m, dict):
            continue
        evidence_lines.append(
            f"  Package={m.get('package')} installed={m.get('installed_version')} "
            f"match_confidence={m.get('confidence')} confirmed={m.get('confirmed_vulnerability')}"
        )
        for c in (m.get("candidates") or [])[:5]:
            evidence_lines.append(
                f"    - {c.get('cve_id')}: {c.get('product')} {c.get('criteria')} "
                f"CVSS={c.get('cvss_score')} {c.get('cvss_severity')}: {c.get('description')}"
            )

    # Bound the configuration context. A Windows collector can return many
    # ephemeral/local ports and hundreds of services; those are useful raw
    # artifacts but would swamp the LLM context. Keep non-loopback TCP ports,
    # de-duplicate by (port,address), and include the security-sensitive/common
    # Windows management ports explicitly.
    selected_ports = []
    seen_ports = set()
    priority_ports = {22, 135, 139, 445, 3389, 5985, 5986, 47001}
    for p in ports:
        if not isinstance(p, dict):
            continue
        protocol = str(p.get("protocol", "")).lower()
        address = str(p.get("local_address", ""))
        try:
            port = int(p.get("local_port"))
        except (TypeError, ValueError):
            continue
        is_loopback = address in {"127.0.0.1", "::1", "[::1]"} or address.startswith("127.")
        if protocol == "tcp" and (not is_loopback or port in priority_ports):
            key = (protocol, address, port)
            if key not in seen_ports:
                selected_ports.append((p, port in priority_ports))
                seen_ports.add(key)

    # Prioritise well-known management/exposure ports, then cap the list.
    selected_ports.sort(key=lambda item: (not item[1], int(item[0].get("local_port", 0))))
    selected_ports = selected_ports[:60]
    ports_block = "\n".join(
        f"  - {p.get('protocol')}/{p.get('local_port')} "
        f"address={p.get('local_address')} process={p.get('process') or 'unknown'}"
        for p, _ in selected_ports
    ) or "  (no non-loopback TCP listeners selected)"

    running_services = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        if str(svc.get("state", "")).lower() in {"running", "active"}:
            running_services.append(svc)
    running_services.sort(key=lambda s: str(s.get("name", "")).lower())
    services_block = "\n".join(
        f"  - {s.get('name', 'unknown')}: {s.get('state', 'unknown')}"
        for s in running_services[:120]
    ) or "  (none active)"

    suid_block = "\n".join(
        f"  - {s.get('path', 'unknown')} owner={s.get('owner') or 'unknown'} "
        f"perms={s.get('permissions') or 'unknown'}"
        for s in suid_binaries[:50] if isinstance(s, dict)
    ) or "  (none reported)"
    kernel_block = "\n".join(
        f"  - {k.get('key')} = {k.get('value')}"
        for k in kernel_params[:50] if isinstance(k, dict)
    ) or "  (none reported)"

    prompt = f"""
You are a local vulnerability and system-hardening assessment engine. Use ONLY the host artifact data and local CVE evidence supplied below.
Do not invent CVE IDs, affected versions, products, installed software, or unsupported remediation facts.

IMPORTANT EVIDENCE RULES:
- A candidate_product_name match is NOT a confirmed vulnerability.
- If vendor/product/version evidence is insufficient, do NOT report a CVE finding.
- Configuration findings may be reported without a CVE, but they must be clearly tied to the supplied host evidence and marked confidence="heuristic".
- Do not call a normal Windows service or standard Windows management port a vulnerability merely because it exists. Flag it only when the supplied evidence supports a meaningful hardening/exposure concern (for example, a management protocol exposed on a non-loopback interface).
- Prefer a small number of defensible findings over speculative findings.

HOST:
  hostname={host.get('hostname')}
  os_family={host.get('os_family')}
  os_version={host.get('os_version')}

INSTALLED PACKAGES:
{chr(10).join(package_lines) or '  (none)'}

LOCAL CVE EVIDENCE:
{chr(10).join(evidence_lines) or '  (none)'}

NON-LOOPBACK / PRIORITY TCP LISTENERS:
{ports_block}

RUNNING SERVICES (bounded list):
{services_block}

SUID / PRIVILEGED BINARIES:
{suid_block}

SECURITY-RELEVANT KERNEL PARAMETERS:
{kernel_block}

Assessment procedure:
1. First check package/CVE evidence. Only promote a CVE when the package/product and affected version are actually supported by the evidence.
2. Separately inspect the host configuration for actionable exposure or hardening issues. Use only observed ports/services/parameters; do not infer that an application is vulnerable merely from an open port.
3. For configuration-only findings, explain the observed evidence and give a concrete hardening action. Use cve_ids=[] and confidence="heuristic".
4. If no evidence supports an actionable issue, return an empty findings list.

{OUTPUT_FORMAT_INSTRUCTIONS}
""".strip()
    return prompt

