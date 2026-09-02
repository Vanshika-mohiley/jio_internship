import csv
import os

inputcsv = "cat3controls.csv"
outputcsv = "category3snippets.csv"
ground_truth = "cat3_groundtruth.csv"

file_header = {
    "sysctl" : "#sysctl conifguration(excerpt) -- e.g./etc/sysctl.conf or 'sysctl -a output",
    "sshd_config" : "# /etc/ssh/sshd_config(excerpt)",
    "auditd.conf" : "# /etc/audit/auditd.conf(excerpt)"
}

def render_line(config_type:str ,parameter: str ,value:str) ->str:
    if config_type == "sysctl":
        return f"{parameter}:{value}"
    elif config_type == "sshd_config":
        return f"{parameter}:{value}"
    elif config_type =="auditd.conf":
        return f"{parameter}:{value}"
    else:
        raise ValueError(f"unknown config type : {config_type}")

with open(inputcsv, newline="",encoding= "utf-8") as f:
    rows = list(csv.DictReader(f))
    
default_by_type = {}

for row in rows:
    ctype = row["config_type"]
    default_by_type.setdefault(ctype,{})
    default_by_type[ctype][row["parameter"]] = row["secure_value"]

os.makedirs(outputcsv,exist_ok=True)
ground_truth_rows =[]

for row in rows:
    ctype = row["config_type"]
    target_param = row["parameter"]

    values =dict(default_by_type[ctype])
    values[target_param] =row["insecure_value"]
    lines= [file_header[ctype],""]

    for param , val in values.items():
        lines.append(render_line(ctype,param,val))

    snippet_text ="\n".join(lines)+"\n"

    filename = f"{row['item_id']}.txt"
    filepath = os.path.join(outputcsv,filename)
    with open(filepath,"w",encoding="utf-8") as out:
        out.write(snippet_text)
    ground_truth_rows.append({"item_id":row["item_id"],
                                "snippet_file":filepath,
                              "config_type":ctype,
                                "misconfigured_parameter":target_param,
                            "current_value_in_snippet": row["insecure_value"],
                             "expected_secure_value":row["secure_value"],"cis_control_id":row["cis_control_id"],
                              "cis_remediation_notes": row["cis_remediation_notes"]})
fieldnames = list(ground_truth_rows[0].keys())
with open(ground_truth,"w",newline="",encoding="utf-8") as f:
    writer = csv.DictWriter(f,fieldnames = fieldnames)
    writer.writeheader()
    writer.writerows(ground_truth_rows)
print(f"generated {len(ground_truth_rows)} snippet in {outputcsv}\n ground truth written in {ground_truth}")