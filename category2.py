import time
import  requests
import csv
from datetime import datetime , timedelta, timezone
from collections import defaultdict
from NVD_api import  extract_cvss , extract_description , api_keys , sleep_second , search_by_date
from category1 import keywords

enddate = datetime.now(timezone.utc)
startdate = enddate - timedelta(days = 90)
pagesize = 200

def fmt(dt : datetime)-> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")

def find_matching_keywords(descriptions : str) -> list:
    desc_lower = descriptions.lower()
    return[kw for kw in keywords if kw in desc_lower]

def built_row(cve_item : dict, matched_keyword :list):
    cve = cve_item["cve"]
    cvss_score ,cvss_vector , cvss_version ,cvss_source = extract_cvss(cve)
    description =extract_description(cve)
    vuln_status = cve.get("vulnStatus","")
    reference_count = len(cve.get("references",[]))
    return {
        "cve_id": cve["id"],
        "matched_keywords": ", ".join(matched_keyword),
        "published": cve.get("published", "")[:10],
        "vuln_status": vuln_status,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_version,
        "cvss_source": cvss_source,
        "reference_count": reference_count,
        "description": description[:250],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        # --- fill in manually ---
        "is_chain_candidate": "",       # yes/no -- related to another CVE in this batch?
        "chain_partner_cve_id": "",     # if yes, which one
        "package": "",
        "installed_version": "",
        "expected_vulnerable": "",
        "source_advisory_url": "",      # vendor/researcher writeup, not just NVD
        "notes": "",
    }
def fetchretry(strt_str , end_str ,pagesize , start_index ,max_retries =3):
    for attempt in range(1,max_retries +1):
        try:
            return search_by_date(strt_str,end_str,result=pagesize, start_index=start_index)
        except requests.exceptions.RequestException as e:
            print(f" Attempt {attempt}/{max_retries} failed : {e}")
            if attempt ==max_retries:
                raise
            time.sleep(sleep_second*2)

def build_category2_dataset(output_path :str = "category2.csv"):
    if not api_keys:
        print("No nvd_api_key running unauthenticated")
    start_str = fmt(startdate)
    end_str = fmt(enddate)
    print(f"date window : {start_str} to {end_str}")
    all_candidates = {}
    start_index = 0
    totalresults = None
    keyword_match_count = defaultdict(int)
    while totalresults is None or start_index<totalresults :
        print(f"fetching page at start index = {start_index}")
        try:
            print(f"results are from {start_str} to {end_str}")
            data = fetchretry(start_str ,end_str , pagesize , start_index)
        except requests.exceptions.RequestException as e:
            print(f" page failed : {e}")
            break
        totalresults = data.get("totalResults", 0)
        page_items = data.get("vulnerabilities",[])
        print(f"{len(page_items)} CVEs this page , {totalresults} total in window")

        for item in page_items:
            description = extract_description(item["cve"])
            matched = find_matching_keywords(description)
            for kw in matched:
                keyword_match_count[kw] +=1

            if not matched:
                continue
            row = built_row(item,matched)
            if row["cve_id"] not in all_candidates:
                all_candidates[row["cve_id"]] = row
        start_index +=pagesize
        time.sleep(sleep_second)
    print(f"\n{len(all_candidates)} telecom-relevant candidates found across full window.")
    print("\n per keyword match counts:")
    for kw in sorted(keyword_match_count , key=keyword_match_count.get ,reverse =True):
        print(f" {kw}: {keyword_match_count[kw]}")

    sorted_candidates = sorted( all_candidates.values(), key= lambda r: r["published"])

    if not sorted_candidates:
        print("\nNo candidate found check date window and keyword list")
        return

    fieldnames = list(sorted_candidates[0].keys())
    with open(output_path , "w", newline="", encoding="utf-8") as f:
        writer= csv.DictWriter(f, fieldnames= fieldnames)
        writer.writeheader()
        writer.writerows(sorted_candidates)
    print(f"\ndone. {len(sorted_candidates)} candidates written to {output_path}")# TEMPORARY DEBUG -- test matching logic on just 5 real CVEs, fast

build_category2_dataset()