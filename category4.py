import csv
import os

inputfile = "category4_controls.csv"
outputfile = "category4_manifest.csv"
ground_truth ="cat4groundtruth.csv"

def parse_list(raw:str)-> list:
    return[item.strip() for item in raw.split(",")]

def parse_sub_field(raw:str)->tuple:
    kind,name=raw.split(":",1)
    return kind.strip(),name.strip()
list_field={"verbs","resources","secret_verbs","policy_types"}
subject_fields ={"subject_binding"}

def parse_value(field:str,raw:str):
    if field in list_field:
        return parse_list(raw)
    if field in subject_fields:
        return parse_sub_field(raw)
    return raw

def yaml_bool(value:str)-> str:
    return "true" if str(value).lower()== "true" else "false"
def yaml_list(items:list)->str:
    rendered =[f"'{item}'" if item=="*" else item for item in items]
    return "[" + ", ".join(rendered) + "]"

def render_pod(values:dict)-> str:
    resource_block =""
    if yaml_bool(values["resources_defined"]) =="true":
        resources_block = (
            "        resources:\n"
            "          limits:\n"
            "            cpu: \"500m\"\n"
            "            memory: \"256Mi\"\n"
            "          requests:\n"
            "            cpu: \"250m\"\n"
            "            memory: \"128Mi\"\n"
        )
    else:
        resources_block = "        # resources block intentionally omitted\n"
 
    return (
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: sample-app\n"
        "  namespace: default\n"
        "spec:\n"
        f"  hostPID: {yaml_bool(values['hostPID'])}\n"
        f"  hostNetwork: {yaml_bool(values['hostNetwork'])}\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: registry.example.com/app:1.0\n"
        "      securityContext:\n"
        f"        privileged: {yaml_bool(values['privileged'])}\n"
        f"        runAsNonRoot: {yaml_bool(values['runAsNonRoot'])}\n"
        f"        allowPrivilegeEscalation: {yaml_bool(values['allowPrivilegeEscalation'])}\n"
        + resources_block
    )
def render_rbac(values:dict) ->str:
    subject_kind , subject_name = values["subject_binding"]
    return(
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n"
        "  name: app-reader\n"
        "rules:\n"
        "  - apiGroups: [\"\"]\n"
        f"    resources: {yaml_list(values['resources'])}\n"
        f"    verbs: {yaml_list(values['verbs'])}\n"
        "  - apiGroups: [\"\"]\n"
        "    resources: [secrets]\n"
        f"    verbs: {yaml_list(values['secrets_verbs'])}\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata:\n"
        "  name: app-reader-binding\n"
        "subjects:\n"
        f"  - kind: {subject_kind}\n"
        f"    name: {subject_name}\n"
        "    namespace: default\n"
        "roleRef:\n"
        "  kind: ClusterRole\n"
        f"  name: {values['role_ref_name']}\n"
        "  apiGroup: rbac.authorization.k8s.io\n"
    )

def render_networkpolicy(values:dict) -> str:
    ingress=(
        "            podSelector:\n"
        "              matchLabels:\n"
        "                role: frontend\n"
        if values["ingress_from"] == "specific"
        else "            {}\n"
    )
    egress_to = (
        "            podSelector:\n"
        "              matchLabels:\n"
        "                role: backend\n"
        if values["egress_to"] == "specific"
        else "            {}\n"
    )
    pod_selector = (
        "  podSelector:\n"
        "    matchLabels:\n"
        "      app: sample-app\n"
        if values["podSelector_scope"] == "specific"
        else "  podSelector: {}\n"
    )
 
    return (
        "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        "  name: app-netpol\n"
        "  namespace: default\n"
        "spec:\n"
        + pod_selector
        + f"  policyTypes: {yaml_list(values['policy_types'])}\n"
        "  ingress:\n"
        "    - from:\n"
        "        - " + ingress.lstrip()
        + "  egress:\n"
        "    - to:\n"
        "        - " + egress_to.lstrip()
    )
renderer={
    "pod_spec": render_pod,
    "rbac": render_rbac,
    "networkpolicy": render_networkpolicy
}

with open(inputfile,newline="") as f:
    rows = list(csv.DictReader(f))

    default_by_type ={}
for row in rows:
    mtype= row["manifest_type"]
    default_by_type.setdefault(mtype,{})
    default_by_type[mtype][row["field"]] =parse_value(row["field"],row["secure_value"])

os.makedirs(outputfile,exist_ok=True)
ground_truth_rows =[]

for row in rows:
    mtype =row["manifest_type"]
    target_field =row["field"]
    values = dict(default_by_type[mtype])
    values[target_field] =parse_value(target_field,row["insecure_value"])

    yaml_text = renderer[mtype](values)
    filename = f"{row['item_id']}.yaml"
    filepath = os.path.join(outputfile,filename)
    with open(filepath,"w") as out:
        out.write(yaml_text)
    ground_truth_rows.append(
        {
            "item_id": row["item_id"],
            "manifest_file": filepath,
            "manifest_type": mtype,
            "misconfigured_field": target_field,
            "current_value_in_manifest": row["insecure_value"],
            "expected_secure_value": row["secure_value"],
            "short_description": row["short_description"],
            "cis_control_id": row["cis_control_id"],
            "cis_remediation_notes": row["cis_remediation_notes"]
        }
    )
fieldnames = list(ground_truth_rows[0].keys())
with open(ground_truth,"w",newline="") as f:
    writer = csv.DictWriter(f,fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(ground_truth_rows)
print(f"generated {len(ground_truth_rows)} manifest in {outputfile}")