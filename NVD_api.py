import os
import  requests

base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
api_keys= os.environ.get("NVD_API_KEYS")
header = {"apikey" : api_keys} if api_keys else{}
sleep_second=0.7 if api_keys else 6.5

#gets the (cvss score,vector,version) from the latest/available cve metric and none if no cvss data present
def extract_cvss(cve : dict): #*******
    metrics =  cve.get("metrics",{})
    for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV40","cvssMetricV2"):
        if key in metrics:
            entry= metrics[key][0]
            m=  entry["cvssData"]
            source  = entry.get("source","unknown")
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString")
            cvss_version = key
            return cvss_score,cvss_vector,cvss_version,source
    return None,None,None,None

#provide description of cve
def extract_description(cve:dict) -> str:
    return next((d["value"] for d in cve.get("descriptions" , []) if d["lang"]=="en"),"No description available")

#CHECKS THE METRIC OF EVALUATION AND IF CVE IS FOUND, IT PRINTS THE CVE DETAILS AS DICTIONARY
def pretty_print_cve(cve_item :dict) -> None: 
    cve = cve_item["cve"]
    cve_id = cve_item["cve"]["id"]
    cvss_score , cvss_vector ,cvss_version = extract_cvss(cve)
    description = extract_description(cve)
        
    print(f"\n{'='*70}")
    print(f"CVE ID:   {cve_id}") #ID OF CVE
    print(f"last modified : {cve.get('lastModified')}") #MODIFICATION DATE
    print(f"CVSS:   {cvss_score}({cvss_version})---{cvss_vector}") #SEVERITY SCORE 
    print(f"Description  :  {description[:200]}...") #DESCIPTION OF CVE

    config =cve.get("configurations" , []) # SEARCHING FOR CONFIGRATIONS OF OS AFFECTED
    if config:
        print("Affected CPEs(sample):")
        for node in config[0].get("nodes",[])[:3]: #PRINTING COMMON PLATFORM ENUMERATION OF AFFECTED OS
            for match in node.get("cpeMatch",[])[:2]:
                print(f"  - {match.get('criteria')}"f"(vulnerable={match.get('vulnerable')})")
    else:
            print("affected CPEs: none listed in record") 

#CVE IN A TIME WINDOW
def search_by_date(start_date : str , end_date: str , result:int=50,start_index:int = 0) -> dict: 
    param ={"pubStartDate": start_date,
            "pubEndDate" :end_date ,
            "resultsPerPage": result,
            "startIndex" :start_index }   #PARAMETERS OF DATE
    response = requests.get(base_url ,params = param, headers =header ,timeout =15) 
    print(response.url)    
    response.raise_for_status()
    return response.json()

#KEYWORD SEARCH FOR CVE
def search_by_keyword(keyword: str, result:int =50)-> dict: 
    param = {"keywordSearch":keyword,"resultsPerPage": result}
    response = requests.get(base_url,params=param ,headers=header,timeout=15)
    print(response.url)
    response.raise_for_status()
    return response.json()

# IF A KEYWORD HAS HIGH SEVERITY CVE RELATED TO IT
def search_high_severity(keyword: str ,result :int =50)-> dict: 
    param = {"keywordSearch":keyword, 
             "cvssV3Severity":"HIGH", 
             "resultsPerPage":result}
    response = requests.get(base_url, params=param,headers=header,timeout=15)
    print(response.url)
    response.raise_for_status()
    return response.json()





