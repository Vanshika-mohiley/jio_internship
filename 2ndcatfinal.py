import csv
from collections import defaultdict
from datetime import datetime

inputpath= "category2.csv"
chainpath= "cat2review.csv"
output= "category2_final.csv"

targetsingles = 15
max_per_keyword = 3
chain_date_window =3

def parse_date(s: str) -> datetime:
    return datetime.strptime(s,"%Y-%m-%d")

def find_chain_candidate(rows : list) -> list:
    pairs = []
    for i, row_a in enumerate(rows):
        kws_a = set(k.strip() for k in row_a["matched_keywords"].split(","))
        date_a = parse_date(row_a["published"])
        for row_b in rows[i+1:]:
            kws_b =set(k.strip() for k in row_b["matched_keywords"].split(","))
            date_b =parse_date(row_b["published"])
            days_apart = abs((date_a - date_b).days)
            shared_keywords = kws_a & kws_b
            if days_apart <= chain_date_window and shared_keywords:
                pairs.append({
                    "cve_id_a": row_a["cve_id"],
                    "cve_id_b": row_b["cve_id"],
                    "days_apart": days_apart,
                    "shared_keywords": ", ".join(shared_keywords),
                    "description_a":row_a["description"][:150],
                    "description_b" : row_b["description"][:150]

                })
    return pairs           
def select_diverse_singles(rows : list ,target:int ,max_per_keyword :int) ->list:
    selected=[]
    keyword_count = defaultdict(int)
    scored_first = sorted(rows,key = lambda r:r["cvss_score"]== "",reverse=False)

    for row in scored_first:
        if len(selected) >=target:
            break
        primary_kw = row["matched_keywords"].split(",")[0].strip()
        if keyword_count[primary_kw]>=max_per_keyword:
            continue
        selected.append(row)
        keyword_count[primary_kw] +=1
    if len(selected)<target:
        for row in scored_first:
            if len(selected) >= target:
                break
            if row not in selected:
                selected.append(row)
    return selected


with open(inputpath , newline="" ,encoding="utf-8") as f:
    all_rows = list(csv.DictReader(f))
print(f"loaded {len(all_rows)} candidate from {inputpath}")

pairs = find_chain_candidate(all_rows)
print(f"\nFound {len(pairs)} plausible chain pairs(published wihtin {chain_date_window} days,sharing keywords.)")

if  pairs:
    with open(chainpath,"w",newline="",encoding="utf-8") as f:
        writer = csv.DictWriter(f,fieldnames = list(pairs[0].keys()))
        writer.writeheader()
        writer.writerows(pairs)
    print(f"written to {chainpath}--read manually and confirm chains")
    flagged_ids = set()
    for p in pairs:
        flagged_ids.add(p["cve_id_a"])
        flagged_ids.add(p["cve_id_b"])
    remaining_rows = [r for r in all_rows if r["cve_id"] not in flagged_ids]
    print(f"\n{len(remaining_rows)} candidate remain for single cve selection aft executing {len(flagged_ids)} flagged as chain items")

singles = select_diverse_singles(remaining_rows,targetsingles,max_per_keyword)
with open(output ,"w",newline="",encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(singles[0].keys()))
    writer.writeheader()
    writer.writerows(singles)
print(f"\n{len(singles)} single cves written to {output}")