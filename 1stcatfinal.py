import csv
from collections import defaultdict
inputpath = "category1.csv"
outputpath= "category1_final.csv"

target_per_tier =10
max_per_keyword_per_tier = 3

def select_diverse(rows : list , target: int , max_per_keyword :int) -> list:
    selected = []
    keyword_count = defaultdict(int)
    for row in rows:
        if len(selected)>=target:
            break
        kw = row["matched_keyword"]
        if keyword_count[kw] >= max_per_keyword :
            continue
        selected.append(row)
        keyword_count[kw] +=1

    if len(selected) < target :
        for row in rows:
            if len(selected) >=  target :
                break
            if row not in selected:
                selected.append(row)
    return selected

with open( inputpath , newline="" , encoding="utf-8") as f:
    all_rows = list(csv.DictReader(f))
print(f"loaded {len(all_rows)} candidates from {inputpath}")

bytier = defaultdict(list)
for row in all_rows:
    tier_label = row["tier"].replace("(suggested)","")
    bytier[tier_label].append(row)

    finalrows = []
for tier_names in ("easy","medium","hard"):
    candidates = bytier.get(tier_names ,[])
    print(f"\n{tier_names} : {len(candidates)} candidate available")
    picked = select_diverse(candidates, target_per_tier, max_per_keyword_per_tier)
    print(f" -> selected {len(picked)}")
    for row in picked:
        row["tier"] = tier_names
    finalrows.extend(picked)
with open(outputpath,"w" , newline='',encoding = "utf-8") as f:
    fieldnames = list(finalrows[0].keys()) if finalrows else []
    writer = csv.DictWriter(f, fieldnames = fieldnames)
    writer.writeheader()
    writer.writerows(finalrows)
print(f"\n done. {len(finalrows)} item written to {outputpath}")







