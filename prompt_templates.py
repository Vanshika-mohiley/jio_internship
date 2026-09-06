#Templates for each 5 categories


#1. CVE known(30)
cveknowntempt = """ consider you are a security analyst performing vulnerability assesment.

task: given a cve id and installed software version,determine wheather that installed version is vulnerable or not to that cve.

cve id: {cve_id}
installed version: {installed_version}

steps before answering:-

1. recall what component/software that cve affects and vulnerable version range.
2. compare installed version against vulnerable range.
3. check cvss score and severity.
4. state your verdict.

note: donot fabricate cve details,decsription,version range or cvss score that you are not confident about or donot recognize the id and explicity state if you are uncofident about a fact.

respond ONLY with valid JSON in this schema:-
{{
"cve_id" : "{cve_id}",
"reseaoning" : "<step-by-step reasoning as single string>",
"vulnerable": <true/false/"unknown">,
"cvvs_score": "<found score>",
"affected_version_range" : "<string or null>",
"confidence" :"<high|medium|low>"}}
"""


#2. CVE novel(20)

cvenoveltemp = """
consider you are a security analyst performing vulnerability assesment.you are being asked about CVEs published after your training cutoff.
treat provided context as your primary source of truth and prefer it over your own recollection.

cve_id : {cve_id}
installed software/version : {installed_version}
retrieved context : \"\"\" {retrieved_context} \"\"\" 

steps before answering:- 
1. check wheather retrived context above identifies this CVE. if it does,then use it as a base for answer above your prior knowledge.

2. if this cve is a part of known multi-cve-chain,i.e 2 or more CVEs that combine to form a single exploit path,identify the related cve ids and explain the link.

3. determine whether installed version falls in vulnerable range.
4.state your final verdict and cite whether your answer was from retrieved or prior knowledge.

*note: if you donot recognize the cve and no retrieved context is provided,say "insufficient information" rather than fabricating any details. Donot fabricate any information.

respond ONLY with valid JSON in this schema:-
{{
"cve_id" : "{cve_id}",
"reseaoning" : "<step-by-step reasoning as single string>",
"vulnerable": <true/false/"unknown">,
"cvvs_score": "<found score>",
"affected_version_range" : "<string or null>",
"answer_source": "<retrived_context|prior_knowledge|insufficent_information>",
"confidence" :"<high|medium|low>"}}

"""


# 3. OS config snippets(25)
osconfigtemp= """you are a security analyst performing an OS hardening review against CIS Benchmark controls.
Configuration source:- {config_source}
configuration snippet: \"\"\" {config_snippet} \"\"\"

steps before answering:-
1. identify each individual setting in the snippet.
2. for each setting, determine whether it matches CIS Benchmark best practice,is a misconfig ,or is it covered by specific CIS control.
3. for each misconfig found,identify its CIS benchmarks control ID and recommended remediation value.
4. summarize overall risk.

note:- only cite CIS control ID if you are confident it is correct. In case of uncertainity of applied control, describe issue and mark control id as "unknown" rather than inventing a new control number.

respond ONLY with valid JSON in this schema:-
{{ "reasoning": "<step-by-step reasoning as single string>",
"misconfigurations":
[ {{
"setting": "<config key/line>",
"current_value" : "<value found>",
"issue" :"<what is wrong>",
"cis_control_id" : "<string or 'unknown'">,
"recommended_value" :"<remediation>"
"confidence" :"<high|medium|low>"}} ] ,

"overall_risk" : "<low|medium|high|critical>",
"confidence": "<high|medium|low>" }}

"""


#4. Kubernetes Manifests(15)

k8smanifesttemp = """ you are a security analyst performing a kubernetes manifest review against CIS kubernetes Benchmark.

Manifest type: {manifest_type}
Manifest YAML : \"\"\" 
{manifest_yaml} \"\"\

steps before an answer :
1. parse the manifest and identify its kind(Pod,RBAC,NetworkPolicy, etc.) and key fields relevant to security (privilege flags,hostPID/hostNetwork,RBAC rules,resource limits,network rules)
2. identify any bad known practices(e.g privilege : true ,wildcard RBAC rules)
3. Map each finding to relevant CIS Kubernetes benchmark control ID where possible.
4. Summarize overall risk and suggest a fix for each finding.
IMPORTANT: Only cite a CIS Kubernetes Benchmark control ID if you are
confident it is correct. If uncertain, describe the issue and mark the
control ID as "unknown" rather than inventing one.
 
Respond with ONLY valid JSON in exactly this schema, no other text:
{{
  "reasoning": "<step-by-step reasoning as a single string>",
  "findings": [
    {{
      "field": "<manifest field/path>",
      "issue": "<what is wrong>",
      "cis_control_id": "<string or 'unknown'>",
      "recommended_fix": "<remediation>"
    }}
  ],
  "overall_risk": "<low|medium|high|critical>",
  "confidence": "<high|medium|low>"
}}
"""



#5. multiartifact scenarios(10)
multiartifacttemp = """ou are a senior security analyst producing a
combined exploitability assessment from multiple system artefacts.
 
Package List:
\"\"\"
{package_list}
\"\"\"
 
Kernel Version: {kernel_version}
 
sysctl Output:
\"\"\"
{sysctl_output}
\"\"\"
 
Service Configuration:
\"\"\"
{service_config}
\"\"\"
 
Think step by step before answering:
1. Review each artefact individually (packages, kernel, sysctl, service config)
   and note any individually concerning finding.
2. Look for combinations across artefacts that create a chained exploitability
   path (e.g. an outdated package + a permissive sysctl setting + an exposed
   service).
3. Construct a full exploitability narrative describing how an attacker could
   realistically chain these findings, step by step.
4. State an overall severity rating for the combined scenario.
 
IMPORTANT: Do not fabricate specific CVE IDs, version numbers, or exploit techniques you are not confident about. If a chain step is plausible but unverified, explicitly label it as speculative in your narrative rather than presenting it as fact.
 
Respond with ONLY valid JSON in exactly this schema, no other text:
{{
  "reasoning": "<step-by-step reasoning as a single string>",
  "individual_findings": [
    {{"artefact": "<packages|kernel|sysctl|service_config>", "issue": "<finding>"}}
  ],
  "exploit_chain_narrative": "<full narrative string, mark speculative steps clearly>",
  "chained_cve_ids_if_known": ["<string>", "..."],
  "overall_severity": "<low|medium|high|critical>",
  "confidence": "<high|medium|low>"
}}"""

