import time
import  requests
import csv
from NVD_api import  extract_cvss , extract_description , api_keys ,search_by_keyword , sleep_second
keywords = [
    "openssl", "nginx", "linux kernel", "kubernetes", "kube-apiserver",
    "containerd", "frr", "asterisk", "freeswitch", "snmp",
    "apache http server", "bind9", "openssh","sip", "rtp", 'sctp', "diameter", "gtp", "voip", "5g", "lte"
]
 
pub_end_date = "2024-06-01T00:00:00.000"
pub_start_date = "2014-01-01T00:00:00.000"
    
    
def buildrow(cve_item : dict , keyword: str):
    cve = cve_item["cve"]
    cvss_score , cvss_vector ,cvss_version,source = extract_cvss(cve)
    if cvss_score is None:
        return None
    description = extract_description(cve)
    reference_count = len(cve.get("references" , []))
    sample_cpe = "" 
    configs = cve.get("configurations",[])
    if configs and configs[0].get("nodes"):
        matches = configs[0]["nodes"][0].get("cpeMatch",[])
        if matches:
            sample_cpe = matches[0].get("criteria","")
    return {
        "cve_id": cve["id"],
        "matched_keyword": keyword,
        "published": cve.get("published", "")[:10],
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_version,
        "cvss_source" : source,
        "reference_count": reference_count,
        "sample_cpe": sample_cpe,
        "description": description[:250],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        "tier": "",
        "package": "",
        "installed_version": "",
        "expected_vulnerable": "",
        "source_advisory_url": "",
        "notes": "",
    }
def build_category1(output_path : str ="category1.csv"):
    if not api_keys:
        print("No NVD_API_KEY set -- running unauthenticated (slower).")
        all_candidates ={}
    for kw in keywords:
        print(f"Querying : {kw}")
        try:
            data = search_by_keyword(kw)
            results= data.get("vulnerabilities" ,[])
        except requests.exceptions.HTTPError as e:
                print(f" skipped '{kw}' due to error : {e}")
                time.sleep(sleep_second)
                continue
        for item in results:
            published = item["cve"].get("published","")
            if   published > pub_end_date or published < pub_start_date:
                continue
            row = buildrow(item,kw)
            if row and row["cve_id"] not in all_candidates:
                all_candidates[row['cve_id']] = row
        print(f"{len(results)} raw results , {len(all_candidates)} total candidates so far")
        time.sleep(sleep_second)

    sorted_candidates = sorted(all_candidates.values(),key =lambda r:r['reference_count'],reverse= True)
    n= len(sorted_candidates)
    for i ,row in enumerate(sorted_candidates):
        if i< n/3:
            row["tier"] = "easy(suggested)"
        elif i< 2 * n/3:
            row["tier"] = "medium(suggested)"
        else:
            row["tier"] = "hard(suggested)"
    fieldnames = list(sorted_candidates[0].keys()) if sorted_candidates else []
    with open(output_path , "w", newline ="", encoding="utf-8") as f:
        writer= csv.DictWriter(f,fieldnames = fieldnames)
        writer.writeheader()
        writer.writerows(sorted_candidates)
    print(f"\nDone. {len(sorted_candidates)} candidates written to {output_path}")
