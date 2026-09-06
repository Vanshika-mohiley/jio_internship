import prompt_templates as pro

templates ={
    "cve_known": pro.cveknowntempt,
    "cve_novel": pro.cvenoveltemp,
    "os_config" : pro.osconfigtemp,
    "k8s_manifest": pro.k8smanifesttemp,
    "multi_artefact": pro.multiartifacttemp
}

def build_prompt(item : dict) -> str:
    category =item.get("category")
    if category not in templates:
        raise ValueError(f"unknown category '{category}'.")
    template = templates[category]
    try:
        return template.format(**item)
    except KeyError as e:
        raise KeyError(f"item for category '{category}' is missing required field {e}")
