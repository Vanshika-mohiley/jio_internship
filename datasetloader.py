import csv
import glob
import os 
import re
def read_csv_rows_safely(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))

def read_text_safely(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()
#category 1 &2 
def loadcveknown(csvpath:str)-> list[dict]:
    items=[]
    for row in read_csv_rows_safely(csvpath):
            items.append({
                "id": row["cve_id"],
                "category": "cve_known",
                "cve_id": row["cve_id"],

                "installed_version": f"{row.get('package','')} {row.get('installed_version','')}".strip(),

                "ground_truth":{
                    "expected_vulnerable":row.get("expected_vulnerable"),
                    "cvss_score":row.get("cvss_score"),
                    "source_advisory_url":row.get("source_advisory_url")
                }
            })
    return items
def loadcvenovel(csv_path : str)-> list[dict]:
    items =[]
    for row in read_csv_rows_safely(csv_path):
            items.append({
                "id": row["cve_id"],
                "category": "cve_novel",
                "cve_id" : row["cve_id"],
                "installed_version": f"{row.get('package','')} {row.get('installed_version','')}".strip(),
                "retrieved_context" : "",

                "ground_truth":
                {
                    "expected_vulnerable": row.get("expected_vulnerable"),
                    "cvss_score" :row.get("cvss_score"),
                    "is_chain_canidate": row.get("is_chain_candidate"),
                    "chain_partner_cve_id":row.get("chain_partner_cve_id"),
                    "source_advisory_url":row.get("source_advisory_url")
                }
            })
    return items
#cateogory 3

def load_os_config(index_csv:str,base_dir: str ="")-> list[dict]:
    items =[]
    for row in read_csv_rows_safely(index_csv):
            file_path = os.path.join(base_dir,row["file_path"])
            with open(file_path) as cf:
                snippet = cf.read()
            items.append({
                "id":row["id"],
                "category":"os_config",
                "config_source" : row["config_source"],
                "config_snippet":snippet,
                "ground_truth": {
                    "cis_control_id": row.get("cis_control_id"),
                    "expected_finding":row.get("expected_finding")
                }
            })
    return items

#category 4(15)
def load_k8s_manifests(index_csv_path: str, base_dir: str = "") -> list[dict]:
    items = []
    for row in read_csv_rows_safely(index_csv_path):
            file_path = os.path.join(base_dir, row["file_path"])
            manifest_yaml = read_text_safely(file_path)
            items.append({
                "id": row["id"],
                "category": "k8s_manifest",
                "manifest_type": row["manifest_type"],
                "manifest_yaml": manifest_yaml,
                "ground_truth": {
                    "cis_control_id": row.get("cis_control_id"),
                    "expected_finding": row.get("expected_finding"),
                },
            })
    return items

#category 5 (10)
SECTION_PATTERN = re.compile(
    r"---\s*(.*?)\s*---\s*\n(.*?)(?=\n---|\Z)", re.DOTALL
)
 
 
def _parse_bundle(text: str) -> dict:
    """Splits a bundle file into its labelled sections."""
    sections = {}
    for header, body in SECTION_PATTERN.findall(text):
        sections[header.strip()] = body.strip()
    return sections
 
 
def load_multi_artefact(bundle_dir: str) -> list[dict]:
    items = []
    for path in sorted(glob.glob(os.path.join(bundle_dir, "*.txt"))):
       text = read_text_safely(path)
       sections = _parse_bundle(text)
       item_id = os.path.splitext(os.path.basename(path))[0]
       reference_section = next(
            (v for k, v in sections.items() if "reference" in k.lower()), "")
       def find_section(keyword, default="N/A"):
            for k, v in sections.items():
                if keyword.lower() in k.lower():
                    return v
            return default
 
       items.append({
            "id": item_id,
            "category": "multi_artefact",
            "package_list": find_section("packages"),
            "kernel_version": find_section("kernel version"),
            "sysctl_output": find_section("sysctl"),
            "service_config": find_section("service configuration"),
            "ground_truth": {
                "reference_note": reference_section,
            },
        })
    return items
 
 

# Combine everything

def load_full_dataset(paths: dict) -> list[dict]:
    
    dataset = []
    dataset += loadcveknown(paths["cve_known_csv"])
    dataset += loadcvenovel(paths["cve_novel_csv"])
    dataset += load_os_config(paths["os_config_index_csv"], paths.get("os_config_base_dir", ""))
    dataset += load_k8s_manifests(paths["k8s_index_csv"], paths.get("k8s_base_dir", ""))
    dataset += load_multi_artefact(paths["multi_artefact_dir"])
    return dataset

 
